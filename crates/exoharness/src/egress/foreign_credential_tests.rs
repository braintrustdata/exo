use super::*;
use hyper::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use std::collections::BTreeMap;

const GUEST_TOKEN: &str = "ghp_guest_token";

struct Received {
    tls: bool,
    path: String,
    headers: HeaderMap,
}

#[derive(Clone, Default)]
struct Requests(Arc<Mutex<Vec<Received>>>);

impl Requests {
    fn take(&self) -> Vec<Received> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

/// Answers TLS and cleartext HTTP on one port, records each request, and sets
/// a cookie on every response.
async fn recording_upstream() -> Result<(Upstream, Requests)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let (ca_pem, tls) = tls_configuration(vec!["api.test".into(), "public.test".into()])?;
    let config = TestUpstream {
        address: listener.local_addr()?,
        ca_pem,
    };
    let requests = Requests::default();
    let recorded = requests.clone();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                incoming = listener.accept() => {
                    let Ok((stream, _)) = incoming else { break; };
                    let tls = tls.clone();
                    let requests = recorded.clone();
                    connections.spawn(async move {
                        let mut first = [0];
                        stream.peek(&mut first).await?;
                        if first[0] == 0x16 {
                            record(tls.accept(stream).await?, true, requests).await
                        } else {
                            record(stream, false, requests).await
                        }
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    Ok((
        Upstream {
            connections: Arc::new(AtomicUsize::new(0)),
            config,
            task,
        },
        requests,
    ))
}

async fn record<T>(stream: T, tls: bool, requests: Requests) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let service = service_fn(move |request: Request<Incoming>| {
        requests.0.lock().unwrap().push(Received {
            tls,
            path: request.uri().path().into(),
            headers: request.headers().clone(),
        });
        async {
            let mut response = Response::new(Full::new(Bytes::from_static(b"ok")));
            response.headers_mut().insert(
                SET_COOKIE,
                HeaderValue::from_static("user_session=upstream; Secure; HttpOnly"),
            );
            Ok::<_, Infallible>(response)
        }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await?;
    Ok(())
}

/// Runs `test` on a current-thread runtime so proxy tasks emit on the capturing
/// thread, and returns the fields of each `sandbox.foreign_credential` signal.
pub(super) fn foreign_credential_signals(
    test: impl std::future::Future<Output = Result<()>>,
) -> Result<Vec<BTreeMap<String, String>>> {
    let mut result = Ok(());
    let events = crate::sandbox_signal::tests::capture(|| {
        result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(anyhow::Error::from)
            .and_then(|runtime| runtime.block_on(test));
    });
    result?;
    Ok(events
        .into_iter()
        .filter(|event| {
            event.target == crate::sandbox_signal::TARGET
                && event.fields["signal"] == "sandbox.foreign_credential"
        })
        .map(|event| event.fields)
        .collect())
}

/// `(sandbox_id, port, stripped, auth_scheme)` for each signal, after checking
/// the fields every signal carries.
fn summarize(signals: &[BTreeMap<String, String>]) -> Vec<(&str, &str, &str, Option<&str>)> {
    signals
        .iter()
        .map(|fields| {
            assert_eq!(fields["source"], "exo.egress.proxy");
            assert_eq!(fields["severity"], "signal");
            assert_eq!(fields["host"], "api.test");
            assert_eq!(fields["method"], "GET");
            assert_eq!(fields["bindings"], "test-credential");
            let mut names: Vec<_> = fields.keys().map(String::as_str).collect();
            names.retain(|name| *name != "auth_scheme");
            assert_eq!(
                names,
                [
                    "bindings",
                    "host",
                    "method",
                    "observed_at",
                    "port",
                    "sandbox_id",
                    "severity",
                    "signal",
                    "source",
                    "stripped",
                ]
            );
            for value in fields.values() {
                assert!(
                    !value.contains(GUEST_TOKEN) && !value.contains(PLACEHOLDER_PREFIX),
                    "{fields:?}"
                );
            }
            (
                fields["sandbox_id"].as_str(),
                fields["port"].as_str(),
                fields["stripped"].as_str(),
                fields.get("auth_scheme").map(String::as_str),
            )
        })
        .collect()
}

fn received<'a>(requests: &'a [Received], path: &str) -> &'a Received {
    requests
        .iter()
        .find(|request| request.path == path)
        .unwrap_or_else(|| panic!("upstream did not receive {path}"))
}

fn assert_stripped(requests: &[Received], path: &str) {
    let request = received(requests, path);
    assert!(!request.headers.contains_key(AUTHORIZATION), "{path}");
    assert!(!request.headers.contains_key(COOKIE), "{path}");
}

#[test]
fn transparent_proxy_strips_foreign_credentials_only_on_bound_hosts() -> Result<()> {
    let signals = foreign_credential_signals(async {
        let (upstream, requests) = recording_upstream().await?;
        let (proxy, client) =
            bound_proxy(&upstream, "strip-transparent", TestResolver::new()).await?;
        let placeholder = proxy.environment()["TEST_API_KEY"].clone();
        let cleartext = reqwest::Client::builder()
            .no_proxy()
            .resolve("api.test", proxy.endpoints().http.into())
            .timeout(Duration::from_secs(10))
            .build()?;
        let guest_cookie = format!("user_session={GUEST_TOKEN}");

        let response = client
            .get("https://api.test/bearer")
            .bearer_auth(GUEST_TOKEN)
            .header(COOKIE, &guest_cookie)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(SET_COOKIE));
        for request in [
            client
                .get("https://api.test/token")
                .header(AUTHORIZATION, format!("token {GUEST_TOKEN}")),
            client.get(format!(
                "https://x-access-token:{GUEST_TOKEN}@api.test/userinfo"
            )),
            client
                .get("https://api.test/mixed")
                .header(AUTHORIZATION, format!("Bearer {placeholder} {GUEST_TOKEN}")),
            client.get("https://api.test/parameter").header(
                AUTHORIZATION,
                format!("token {placeholder}; token={GUEST_TOKEN}"),
            ),
            client
                .get("https://api.test/duplicate")
                .header(AUTHORIZATION, format!("Bearer {GUEST_TOKEN}"))
                .header(AUTHORIZATION, format!("token {GUEST_TOKEN}")),
            client
                .get("https://api.test/cookie")
                .header(COOKIE, &guest_cookie),
            cleartext
                .get("http://api.test/cleartext")
                .bearer_auth(GUEST_TOKEN)
                .header(COOKIE, &guest_cookie),
            client
                .get("https://api.test/placeholder")
                .bearer_auth(&placeholder),
            client
                .get("https://api.test/basic")
                .basic_auth("x-access-token", Some(&placeholder)),
            client.get("https://api.test/anonymous"),
        ] {
            let response = request.send().await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(!response.headers().contains_key(SET_COOKIE));
        }
        let response = client
            .get("https://public.test/unbound")
            .bearer_auth(GUEST_TOKEN)
            .header(COOKIE, &guest_cookie)
            .send()
            .await?;
        assert_eq!(
            response.headers()[SET_COOKIE],
            "user_session=upstream; Secure; HttpOnly"
        );

        let requests = requests.take();
        for path in [
            "/bearer",
            "/token",
            "/userinfo",
            "/mixed",
            "/parameter",
            "/duplicate",
            "/cookie",
            "/cleartext",
            "/anonymous",
        ] {
            assert_stripped(&requests, path);
        }
        assert!(!received(&requests, "/cleartext").tls);
        assert_eq!(
            received(&requests, "/placeholder").headers[AUTHORIZATION],
            "Bearer canary-v1"
        );
        assert_eq!(
            received(&requests, "/basic").headers[AUTHORIZATION],
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("x-access-token:canary-v1")
            )
            .as_str()
        );
        let unbound = &received(&requests, "/unbound").headers;
        assert_eq!(
            unbound[AUTHORIZATION],
            format!("Bearer {GUEST_TOKEN}").as_str()
        );
        assert_eq!(unbound[COOKIE], guest_cookie.as_str());
        proxy.shutdown().await
    })?;
    assert_eq!(
        summarize(&signals),
        [
            (
                "strip-transparent",
                "443",
                "authorization,cookie",
                Some("bearer")
            ),
            ("strip-transparent", "443", "authorization", Some("token")),
            ("strip-transparent", "443", "authorization", Some("basic")),
            ("strip-transparent", "443", "authorization", Some("bearer")),
            ("strip-transparent", "443", "authorization", Some("token")),
            (
                "strip-transparent",
                "443",
                "authorization",
                Some("bearer,token")
            ),
            ("strip-transparent", "443", "cookie", None),
            (
                "strip-transparent",
                "80",
                "authorization,cookie",
                Some("bearer")
            ),
        ]
    );
    Ok(())
}

#[test]
fn unrestricted_proxy_intercepts_bound_hosts_and_tunnels_others() -> Result<()> {
    let signals = foreign_credential_signals(async {
        let (upstream, requests) = recording_upstream().await?;
        let mut policy = policy();
        policy.networking = SandboxNetworkPolicy::Unrestricted;
        let proxy = upstream
            .proxy_with_policy(
                host_ip()?,
                "strip-unrestricted",
                TestResolver::new(),
                policy,
            )
            .await?;
        proxy.bind_source(host_ip()?).await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_pem(proxy.ca_pem().as_bytes())?)
            .add_root_certificate(reqwest::Certificate::from_pem(
                upstream.config.ca_pem.as_bytes(),
            )?)
            .resolve("api.test", proxy.endpoints().https.into())
            .resolve("public.test", proxy.endpoints().https.into())
            .timeout(Duration::from_secs(10))
            .build()?;
        for url in ["https://api.test/bound", "https://public.test/tunneled"] {
            let response = client
                .get(url)
                .bearer_auth(GUEST_TOKEN)
                .header(COOKIE, "user_session=guest")
                .send()
                .await?;
            assert_eq!(
                response.headers().contains_key(SET_COOKIE),
                url.contains("public.test"),
                "{url}"
            );
        }
        let requests = requests.take();
        assert_stripped(&requests, "/bound");
        let tunneled = &received(&requests, "/tunneled").headers;
        assert_eq!(
            tunneled[AUTHORIZATION],
            format!("Bearer {GUEST_TOKEN}").as_str()
        );
        assert_eq!(tunneled[COOKIE], "user_session=guest");
        proxy.shutdown().await
    })?;
    assert_eq!(
        summarize(&signals),
        [(
            "strip-unrestricted",
            "443",
            "authorization,cookie",
            Some("bearer")
        )]
    );
    Ok(())
}

#[test]
fn explicit_and_hosted_proxies_strip_foreign_credentials() -> Result<()> {
    use super::explicit::ExplicitProxy;
    let signals = foreign_credential_signals(async {
        let (upstream, requests) = recording_upstream().await?;
        let explicit = ExplicitProxy::with_listener(
            State::new(
                identity("strip-explicit"),
                policy(),
                Some(TestResolver::new()),
                Arc::new(upstream.config.clone()),
            )?,
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?,
            "127.0.0.1",
        )
        .await?;
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&explicit.environment["HTTPS_PROXY"])?)
            .add_root_certificate(reqwest::Certificate::from_pem(explicit.ca_pem.as_bytes())?)
            .timeout(Duration::from_secs(10))
            .build()?;
        for url in [
            "https://api.test/explicit-connect",
            "http://api.test/explicit-http",
        ] {
            let response = client.get(url).bearer_auth(GUEST_TOKEN).send().await?;
            assert_eq!(response.status(), StatusCode::OK, "{url}");
            assert!(!response.headers().contains_key(SET_COOKIE), "{url}");
        }
        explicit.close();

        let authorizer = TestProxyAuthorizer::new(&upstream)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_connect_proxy(
            listener,
            authorizer.clone(),
            cancel.clone(),
        ));
        let hosted = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!(
                "http://sandbox:first@{address}"
            ))?)
            .add_root_certificate(reqwest::Certificate::from_pem(
                authorizer.ca_pem.as_bytes(),
            )?)
            .timeout(Duration::from_secs(10))
            .build()?;
        let response = hosted
            .get("https://api.test/hosted-connect")
            .header(AUTHORIZATION, format!("token {GUEST_TOKEN}"))
            .header(COOKIE, "user_session=guest")
            .send()
            .await?;
        assert!(!response.headers().contains_key(SET_COOKIE));
        drop(hosted);
        cancel.cancel();
        server.await??;

        // serve_https_connect hands the tunnel to https_connection after the
        // caller's CONNECT; its public form only reaches public upstreams.
        let placeholders = HashMap::from([(
            "TEST_API_KEY".into(),
            "exo_egress_0123456789abcdef0123456789abcdef".into(),
        )]);
        let state = Arc::new(State::new_with_placeholders(
            identity("strip-connect"),
            policy(),
            Some(TestResolver::new()),
            Arc::new(upstream.config.clone()),
            Some(&placeholders),
            None,
        )?);
        let (ca_pem, tls) = tls_configuration(vec!["api.test".into()])?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            https_connection(stream, tls, state, Some("api.test")).await
        });
        let tunnel = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes())?)
            .resolve("api.test", address)
            .build()?;
        let response = tunnel
            .get("https://api.test/https-connect")
            .basic_auth("x-access-token", Some(GUEST_TOKEN))
            .header("connection", "close")
            .send()
            .await?;
        assert!(!response.headers().contains_key(SET_COOKIE));
        drop(tunnel);
        server.await??;

        let requests = requests.take();
        for path in [
            "/explicit-connect",
            "/explicit-http",
            "/hosted-connect",
            "/https-connect",
        ] {
            assert_stripped(&requests, path);
        }
        Ok(())
    })?;
    assert_eq!(
        summarize(&signals),
        [
            ("strip-explicit", "443", "authorization", Some("bearer")),
            ("strip-explicit", "80", "authorization", Some("bearer")),
            ("first", "443", "authorization,cookie", Some("token")),
            ("strip-connect", "443", "authorization", Some("basic")),
        ]
    );
    Ok(())
}
