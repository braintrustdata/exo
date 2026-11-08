//! Credential substitution shared by native proxies and hosted runtimes.
use crate::EgressCredentialBinding;
use anyhow::{Context, Result, anyhow, ensure};
use async_trait::async_trait;
use base64::Engine;
use http::{
    Method,
    header::{AUTHORIZATION, CONNECTION, COOKIE, HOST, HeaderMap, HeaderName, HeaderValue},
};
use std::collections::{HashMap, HashSet};
pub mod session;
pub mod vault;
pub const PLACEHOLDER_PREFIX: &str = "exo_egress_";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EgressIdentity {
    pub sandbox_id: String,
    pub scope: crate::ResourceScope,
}

#[derive(Debug)]
pub struct EgressDestination {
    pub host: String,
    pub port: u16,
    pub method: Method,
    pub path: String,
}

/// Looks up a binding for this sandbox's agent/thread on every use. The local
/// implementation reads Exo's encrypted store; a hosted implementation can use
/// its own vault and authorization. Only the proxy receives the returned value.
/// Return [`EgressError::Rejected`] to explain a denial safely to the sandbox.
#[async_trait]
pub trait EgressCredentialResolver: Send + Sync {
    async fn resolve(
        &self,
        identity: &EgressIdentity,
        binding_name: &str,
        destination: &EgressDestination,
    ) -> Result<String, EgressError>;

    async fn refresh(
        &self,
        _identity: &EgressIdentity,
        _binding_name: &str,
        _destination: &EgressDestination,
        _rejected: &str,
    ) -> Result<Option<String>, EgressError> {
        Ok(None)
    }
}

pub(crate) struct Binding {
    pub(crate) config: EgressCredentialBinding,
    hosts: HashSet<String>,
    pub(crate) placeholder: String,
}

impl Binding {
    pub(crate) fn covers_host(&self, host: &str) -> bool {
        self.hosts.contains(host)
    }

    pub(crate) fn permits_header(&self, destination: &EgressDestination) -> bool {
        self.config.injection_location.header
            && self.hosts.contains(&destination.host)
            && crate::CredentialDestination::url(&format!(
                "https://{}:{}{}",
                destination.host, destination.port, destination.path
            ))
            .is_ok_and(|destination| self.config.networking.permits(&destination))
    }
}

pub(crate) fn prepare_bindings(
    credentials: Vec<EgressCredentialBinding>,
    placeholders: Option<&HashMap<String, String>>,
) -> Result<Vec<Binding>> {
    let mut variables = HashSet::new();
    let mut values = HashSet::new();
    let mut bindings = Vec::new();
    for mut config in credentials {
        config.networking = config.networking.normalized()?;
        let hosts = config.networking.hosts()?;
        ensure!(
            !config.name.is_empty(),
            "credential binding name is required"
        );
        ensure!(
            !config.environment_variable.is_empty()
                && config
                    .environment_variable
                    .bytes()
                    .enumerate()
                    .all(|(i, c)| c == b'_'
                        || c.is_ascii_alphabetic()
                        || (i > 0 && c.is_ascii_digit())),
            "invalid credential environment variable"
        );
        ensure!(
            variables.insert(config.environment_variable.clone()),
            "duplicate credential environment variable"
        );
        let placeholder = if let Some(placeholders) = placeholders {
            let value = placeholders
                .get(&config.environment_variable)
                .context("missing credential placeholder")?;
            ensure!(
                value.len() == PLACEHOLDER_PREFIX.len() + 32
                    && value.starts_with(PLACEHOLDER_PREFIX)
                    && value[PLACEHOLDER_PREFIX.len()..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    && values.insert(value.clone()),
                "invalid or duplicate credential placeholder"
            );
            value.clone()
        } else {
            format!("{PLACEHOLDER_PREFIX}{}", uuid::Uuid::new_v4().simple())
        };
        bindings.push(Binding {
            config,
            hosts,
            placeholder,
        });
    }
    Ok(bindings)
}

pub(crate) fn validate_credentials(
    bindings: &[Binding],
    headers: &HeaderMap,
    destination: &EgressDestination,
    tls: bool,
) -> Result<()> {
    for (header, value) in headers {
        let basic = basic_credential_placeholder(header, value)?;
        let value = basic
            .as_deref()
            .map(str::as_bytes)
            .unwrap_or(value.as_bytes());
        if !contains_placeholder(value) {
            continue;
        }
        ensure!(tls, "credential substitution requires HTTPS");
        ensure!(
            !hop_header(header) && header != HOST && header != "content-length",
            "credential cannot rewrite HTTP routing or framing"
        );
        ensure!(
            headers.get_all(header).iter().count() == 1,
            "duplicate credential header"
        );
        let mut unresolved = std::str::from_utf8(value)?.to_owned();
        for binding in bindings {
            if binding.permits_header(destination) {
                unresolved = unresolved.replace(&binding.placeholder, "");
            }
        }
        ensure!(
            !unresolved.contains(PLACEHOLDER_PREFIX),
            "credential placeholder does not match this request"
        );
    }
    Ok(())
}

pub(crate) async fn substitute_credentials(
    bindings: &[Binding],
    headers: &mut HeaderMap,
    destination: &EgressDestination,
    identity: &EgressIdentity,
    resolver: &dyn EgressCredentialResolver,
) -> Result<Vec<(String, String)>, EgressError> {
    let mut credentials = Vec::new();
    for (header, header_value) in headers.iter_mut() {
        let basic = basic_credential_placeholder(header, header_value)?;
        if basic.is_none() && !contains_placeholder(header_value.as_bytes()) {
            continue;
        }
        let encode_basic = basic.is_some();
        let mut replacement = match basic {
            Some(value) => value,
            None => header_value
                .to_str()
                .context("invalid credential header")?
                .to_owned(),
        };
        for binding in bindings {
            if !binding.permits_header(destination) || !replacement.contains(&binding.placeholder) {
                continue;
            }
            let value = resolver
                .resolve(identity, &binding.config.name, destination)
                .await?;
            replacement = replacement.replace(&binding.placeholder, &value);
            credentials.push((binding.config.name.clone(), value));
        }
        if encode_basic {
            replacement = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(replacement)
            );
        }
        let mut value = HeaderValue::from_str(&replacement)
            .map_err(|_| anyhow!("credential cannot be used in an HTTP header"))?;
        value.set_sensitive(true);
        *header_value = value;
    }
    Ok(credentials)
}

fn basic_credential_placeholder(
    header: &HeaderName,
    value: &HeaderValue,
) -> Result<Option<String>> {
    if header == http::header::AUTHORIZATION
        && let Ok(value) = value.to_str()
        && let Some((scheme, encoded)) = value.split_once(' ')
        && scheme.eq_ignore_ascii_case("basic")
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded)
        && contains_placeholder(&decoded)
    {
        return Ok(Some(
            String::from_utf8(decoded).context("invalid Basic credential")?,
        ));
    }
    Ok(None)
}

fn contains_placeholder(value: &[u8]) -> bool {
    value
        .windows(PLACEHOLDER_PREFIX.len())
        .any(|s| s == PLACEHOLDER_PREFIX.as_bytes())
}

pub(crate) fn hop_header(name: &HeaderName) -> bool {
    // HeaderName::as_str() always returns lowercase; no normalization is needed.
    // https://docs.rs/http/latest/http/header/struct.HeaderName.html#method.as_str
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

pub fn strip_hop_headers(headers: &mut HeaderMap) -> Result<()> {
    let mut remove = Vec::new();
    // The same rule also removes custom fields named by Connection.
    for value in headers.get_all(CONNECTION) {
        remove.extend(
            value
                .to_str()?
                .split(',')
                .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok()),
        );
    }
    remove.extend(headers.keys().filter(|name| hop_header(name)).cloned());
    for name in remove {
        headers.remove(name);
    }
    Ok(())
}

/// Validated header bindings and their opaque sandbox environment values.
pub struct CredentialBindings {
    bindings: Vec<Binding>,
}
impl CredentialBindings {
    pub fn new(
        credentials: Vec<EgressCredentialBinding>,
        placeholders: Option<&HashMap<String, String>>,
    ) -> Result<Self> {
        Ok(Self {
            bindings: prepare_bindings(credentials, placeholders)?,
        })
    }
    pub fn environment(&self) -> HashMap<String, String> {
        self.bindings
            .iter()
            .map(|binding| {
                (
                    binding.config.environment_variable.clone(),
                    binding.placeholder.clone(),
                )
            })
            .collect()
    }
    pub fn validate(
        &self,
        headers: &HeaderMap,
        destination: &EgressDestination,
        tls: bool,
    ) -> Result<()> {
        validate_credentials(&self.bindings, headers, destination, tls)
    }
    pub async fn substitute(
        &self,
        headers: &mut HeaderMap,
        destination: &EgressDestination,
        identity: &EgressIdentity,
        resolver: &dyn EgressCredentialResolver,
    ) -> Result<(), EgressError> {
        self.substitute_tracked(headers, destination, identity, resolver)
            .await?;
        Ok(())
    }

    /// The substituted values let the proxy refresh only credentials rejected by the upstream.
    pub async fn substitute_tracked(
        &self,
        headers: &mut HeaderMap,
        destination: &EgressDestination,
        identity: &EgressIdentity,
        resolver: &dyn EgressCredentialResolver,
    ) -> Result<Vec<(String, String)>, EgressError> {
        substitute_credentials(&self.bindings, headers, destination, identity, resolver).await
    }
}

/// Failures while authorizing or forwarding an egress request.
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    /// A denial with a sandbox-safe message, returned as plain-text HTTP 403.
    #[error("{0}")]
    Rejected(String),
    /// A policy denial whose diagnostic must not be exposed by the native proxy.
    #[error("egress request denied: {0}")]
    Denied(#[source] anyhow::Error),
    /// I/O, corrupt stored state, or another internal failure.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub fn denied(error: impl Into<anyhow::Error>) -> EgressError {
    EgressError::Denied(error.into())
}

pub fn credential_fingerprint(value: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

/// Canonical HTTP destination shared by transparent and platform interception.
pub fn http_destination(url: &url::Url, method: Method) -> Result<EgressDestination> {
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "invalid HTTP destination"
    );
    let host = crate::types::canonical_egress_host(url.host_str().context("missing hostname")?)?;
    let port = url
        .port_or_known_default()
        .context("missing destination port")?;
    ensure!(
        matches!((url.scheme(), port), ("http", 80) | ("https", 443)),
        "only standard HTTP ports are supported"
    );
    Ok(EgressDestination {
        host,
        port,
        method,
        path: url[url::Position::BeforePath..url::Position::AfterQuery].into(),
    })
}

/// Compiled network rules used by native listeners and hosted interception.
pub(crate) struct NetworkPolicy {
    hosts: HashSet<String>,
    unrestricted: bool,
    enabled: bool,
    ports: Option<Vec<u16>>,
}
impl NetworkPolicy {
    pub(crate) fn new(policy: &crate::EgressPolicy) -> Result<Self> {
        ensure!(
            policy
                .allowed_tcp_ports
                .as_ref()
                .is_none_or(|ports| !ports.contains(&0)),
            "policy.allowed_tcp_ports cannot contain port zero"
        );
        let hosts = match &policy.networking {
            crate::SandboxNetworkPolicy::Limited { allowed_hosts } => {
                crate::types::canonical_egress_hosts(allowed_hosts)?
            }
            _ => HashSet::new(),
        };
        Ok(Self {
            hosts,
            unrestricted: policy.networking == crate::SandboxNetworkPolicy::Unrestricted,
            enabled: policy.networking_enabled(),
            ports: policy.allowed_tcp_ports.clone(),
        })
    }
    #[cfg(feature = "basic-backend")]
    pub(crate) fn hosts(&self) -> &HashSet<String> {
        &self.hosts
    }
    #[cfg(feature = "basic-backend")]
    pub(crate) fn unrestricted(&self) -> bool {
        self.unrestricted
    }
    pub(crate) fn permits_host(&self, host: &str) -> bool {
        self.enabled && (self.unrestricted || self.hosts.contains(host))
    }
    pub(crate) fn check_port(&self, port: u16) -> Result<()> {
        ensure!(
            port != 0
                && self
                    .ports
                    .as_ref()
                    .is_none_or(|ports| ports.contains(&port)),
            "TCP port is not allowed"
        );
        Ok(())
    }
    pub(crate) fn authorize(&self, destination: &EgressDestination) -> Result<()> {
        self.check_port(destination.port)?;
        ensure!(
            self.permits_host(&destination.host),
            "network destination denied"
        );
        Ok(())
    }
}

pub(crate) async fn rewrite_headers(
    bindings: &[Binding],
    headers: &mut HeaderMap,
    destination: &EgressDestination,
    tls: bool,
    identity: &EgressIdentity,
    resolver: &dyn EgressCredentialResolver,
) -> Result<Vec<(String, String)>, EgressError> {
    if headers.contains_key(http::header::UPGRADE) {
        return Err(denied(anyhow!("protocol upgrades are not supported")));
    }
    if destination.method == Method::CONNECT {
        return Err(denied(anyhow!("CONNECT is not supported")));
    }
    validate_credentials(bindings, headers, destination, tls).map_err(denied)?;
    strip_foreign_credentials(bindings, headers, destination, &identity.sandbox_id);
    strip_hop_headers(headers).map_err(denied)?;
    let credentials =
        substitute_credentials(bindings, headers, destination, identity, resolver).await?;
    headers.remove(HOST);
    headers.remove("content-length");
    Ok(credentials)
}

/// A host named by a binding receives credentials only from the resolver.
/// `Cookie` is removed, and so is `Authorization` unless it is the only one and
/// [`placeholder_authorization`] accepts it. Runs after [`validate_credentials`]
/// so a placeholder this request may not use is still rejected, not removed.
#[cfg_attr(
    not(all(not(target_arch = "wasm32"), feature = "basic-backend")),
    allow(unused_variables)
)]
fn strip_foreign_credentials(
    bindings: &[Binding],
    headers: &mut HeaderMap,
    destination: &EgressDestination,
    sandbox_id: &str,
) {
    if !bindings
        .iter()
        .any(|binding| binding.covers_host(&destination.host))
    {
        return;
    }
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let authorization = match (values.next(), values.next()) {
        (None, _) => None,
        (Some(value), None) if placeholder_authorization(bindings, destination, value) => None,
        _ => Some(AuthSchemes::of(headers.get_all(AUTHORIZATION))),
    };
    if authorization.is_some() {
        headers.remove(AUTHORIZATION);
    }
    let cookie = headers.remove(COOKIE).is_some();
    if authorization.is_none() && !cookie {
        return;
    }
    #[cfg(all(not(target_arch = "wasm32"), feature = "basic-backend"))]
    signal_foreign_credentials(
        bindings,
        destination,
        sandbox_id,
        authorization.as_ref(),
        cookie,
    );
}

/// Names the removed headers and the bindings covering the host, never values.
#[cfg(all(not(target_arch = "wasm32"), feature = "basic-backend"))]
fn signal_foreign_credentials(
    bindings: &[Binding],
    destination: &EgressDestination,
    sandbox_id: &str,
    authorization: Option<&AuthSchemes>,
    cookie: bool,
) {
    let mut names = Vec::new();
    for binding in bindings {
        let name = binding.config.name.as_str();
        if binding.covers_host(&destination.host) && !names.contains(&name) {
            names.push(name);
        }
    }
    let method = destination.method.as_str();
    crate::sandbox_signal::sandbox_signal!(
        signal,
        "sandbox.foreign_credential",
        sandbox_id = sandbox_id,
        source = "exo.egress.proxy",
        host = destination.host.as_str(),
        method = &method[..method.floor_char_boundary(32)],
        port = destination.port,
        stripped = match (authorization.is_some(), cookie) {
            (true, true) => "authorization,cookie",
            (true, false) => "authorization",
            (false, _) => "cookie",
        },
        auth_scheme = authorization.map(tracing::field::display),
        bindings = names.join(","),
    );
}

/// Whether `value` is exactly one placeholder this destination permits:
/// `<placeholder>`, `<scheme> <placeholder>`, or Basic credentials whose
/// password is the placeholder. Any other text could carry the client's own
/// secret, including parameters that some servers read as the credential.
fn placeholder_authorization(
    bindings: &[Binding],
    destination: &EgressDestination,
    value: &HeaderValue,
) -> bool {
    let Ok(value) = value.to_str() else {
        return false;
    };
    let mut placeholders = bindings
        .iter()
        .filter(|binding| binding.permits_header(destination))
        .map(|binding| binding.placeholder.as_str());
    if let Some((scheme, encoded)) = value.split_once(' ')
        && scheme.eq_ignore_ascii_case("basic")
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded)
    {
        return std::str::from_utf8(&decoded)
            .ok()
            .and_then(|decoded| decoded.split_once(':'))
            .is_some_and(|(_, password)| placeholders.any(|placeholder| password == placeholder));
    }
    placeholders.any(|placeholder| {
        let Some(prefix) = value.strip_suffix(placeholder) else {
            return false;
        };
        let scheme = prefix.trim_end_matches(' ');
        prefix.is_empty()
            || (scheme.len() < prefix.len()
                && is_token(scheme)
                && !scheme.contains(PLACEHOLDER_PREFIX))
    })
}

// RFC 9110 section 5.6.2.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// Schemes reported for removed `Authorization` values; any other is `other`.
const AUTH_SCHEMES: [&str; 4] = ["basic", "bearer", "token", "other"];

/// Schemes of removed `Authorization` values, named from [`AUTH_SCHEMES`] so no
/// part of a value is ever reported.
struct AuthSchemes([bool; AUTH_SCHEMES.len()]);

impl AuthSchemes {
    fn of<'a>(values: impl IntoIterator<Item = &'a HeaderValue>) -> Self {
        let mut seen = [false; AUTH_SCHEMES.len()];
        for value in values {
            let scheme = value.as_bytes().split(|byte| *byte == b' ').next();
            let index = AUTH_SCHEMES
                .iter()
                .position(|known| {
                    scheme.is_some_and(|scheme| scheme.eq_ignore_ascii_case(known.as_bytes()))
                })
                .unwrap_or(AUTH_SCHEMES.len() - 1);
            seen[index] = true;
        }
        Self(seen)
    }
}

impl std::fmt::Display for AuthSchemes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut separator = "";
        for (scheme, seen) in AUTH_SCHEMES.iter().zip(self.0) {
            if seen {
                write!(formatter, "{separator}{scheme}")?;
                separator = ",";
            }
        }
        Ok(())
    }
}
impl CredentialBindings {
    /// Validates, removes `Cookie` and non-placeholder `Authorization` on hosts a
    /// binding names, and substitutes placeholders. Callers forwarding the
    /// response from such a host must remove its `Set-Cookie` headers.
    pub async fn rewrite_headers(
        &self,
        headers: &mut HeaderMap,
        destination: &EgressDestination,
        tls: bool,
        identity: &EgressIdentity,
        resolver: &dyn EgressCredentialResolver,
    ) -> Result<Vec<(String, String)>, EgressError> {
        rewrite_headers(
            &self.bindings,
            headers,
            destination,
            tls,
            identity,
            resolver,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CredentialInjectionLocation, CredentialNetworkPolicy};

    const PLACEHOLDER: &str = "exo_egress_0123456789abcdef0123456789abcdef";
    const OTHER_PLACEHOLDER: &str = "exo_egress_fedcba9876543210fedcba9876543210";

    fn bindings() -> Vec<Binding> {
        let binding = |name: &str, variable: &str, networking| EgressCredentialBinding {
            name: name.into(),
            environment_variable: variable.into(),
            networking,
            injection_location: CredentialInjectionLocation { header: true },
        };
        prepare_bindings(
            vec![
                binding(
                    "github",
                    "GH_TOKEN",
                    CredentialNetworkPolicy::Limited {
                        allowed_hosts: vec!["api.test".into()],
                    },
                ),
                binding(
                    "graphql",
                    "GRAPHQL_TOKEN",
                    CredentialNetworkPolicy::Destinations {
                        allowed_destinations: vec![
                            crate::CredentialDestination::url("https://graph.test/graphql")
                                .unwrap(),
                        ],
                    },
                ),
            ],
            Some(&HashMap::from([
                ("GH_TOKEN".into(), PLACEHOLDER.into()),
                ("GRAPHQL_TOKEN".into(), OTHER_PLACEHOLDER.into()),
            ])),
        )
        .unwrap()
    }

    fn destination(host: &str, path: &str) -> EgressDestination {
        EgressDestination {
            host: host.into(),
            port: 443,
            method: Method::POST,
            path: path.into(),
        }
    }

    fn basic(credentials: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        )
    }

    fn strip(destination: &EgressDestination, headers: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        strip_foreign_credentials(&bindings(), &mut map, destination, "sandbox");
        map
    }

    #[test]
    fn authorization_survives_only_as_one_permitted_placeholder() {
        let api = destination("api.test", "/repos/org/repo/git/refs");
        for (value, kept) in [
            (format!("Bearer {PLACEHOLDER}"), true),
            (format!("token {PLACEHOLDER}"), true),
            (format!("Bearer  {PLACEHOLDER}"), true),
            (PLACEHOLDER.to_owned(), true),
            (format!("Basic {PLACEHOLDER}"), true),
            (basic(&format!("x-access-token:{PLACEHOLDER}")), true),
            ("Bearer ghp_guest".into(), false),
            ("token ghp_guest".into(), false),
            ("ghp_guest".into(), false),
            (basic("x-access-token:ghp_guest"), false),
            (basic(&format!("{PLACEHOLDER}:ghp_guest")), false),
            (
                basic(&format!("x-access-token:{PLACEHOLDER}ghp_guest")),
                false,
            ),
            (basic(&format!("x-access-token:{OTHER_PLACEHOLDER}")), false),
            (format!("Bearer {OTHER_PLACEHOLDER}"), false),
            (format!("Bearer ghp_guest {PLACEHOLDER}"), false),
            (format!("ghp_guest{PLACEHOLDER}"), false),
            (format!("Bearer {PLACEHOLDER} ghp_guest"), false),
            (format!("Bearer {PLACEHOLDER}ghp_guest"), false),
            (format!("Bearer {PLACEHOLDER}, token ghp_guest"), false),
            (format!("Token {PLACEHOLDER}; scope=read"), false),
            (format!("token {PLACEHOLDER}; token=ghp_guest"), false),
            (format!("Token {PLACEHOLDER};ghp_guest"), false),
            (format!("Bearer {PLACEHOLDER}; extra={PLACEHOLDER}"), false),
            (format!("{PLACEHOLDER} {PLACEHOLDER}"), false),
            (format!("Basic {PLACEHOLDER} {PLACEHOLDER}"), false),
        ] {
            let headers = strip(&api, &[("authorization", &value)]);
            assert_eq!(headers.contains_key(AUTHORIZATION), kept, "{value}");
        }
        let bearer = format!("Bearer {PLACEHOLDER}");
        let headers = strip(
            &api,
            &[("authorization", &bearer), ("authorization", &bearer)],
        );
        assert!(!headers.contains_key(AUTHORIZATION));
    }

    #[test]
    fn bound_hosts_lose_cookies_and_other_hosts_keep_everything() {
        let bearer = format!("Bearer {PLACEHOLDER}");
        let headers = strip(
            &destination("api.test", "/user"),
            &[
                ("authorization", &bearer),
                ("cookie", "user_session=guest"),
                ("cookie", &format!("token={PLACEHOLDER}")),
                ("x-api-key", "guest-key"),
            ],
        );
        assert_eq!(headers[AUTHORIZATION], bearer.as_str());
        assert!(!headers.contains_key(COOKIE));
        assert_eq!(headers["x-api-key"], "guest-key");

        // A destination-limited binding still covers its whole host.
        let graphql = format!("Bearer {OTHER_PLACEHOLDER}");
        for (path, kept) in [("/graphql", true), ("/repos", false)] {
            let headers = strip(
                &destination("graph.test", path),
                &[("authorization", &graphql)],
            );
            assert_eq!(headers.contains_key(AUTHORIZATION), kept, "{path}");
        }

        let headers = strip(
            &destination("public.test", "/"),
            &[
                ("authorization", "Bearer ghp_guest"),
                ("cookie", "user_session=guest"),
            ],
        );
        assert_eq!(headers[AUTHORIZATION], "Bearer ghp_guest");
        assert_eq!(headers[COOKIE], "user_session=guest");
    }

    #[test]
    fn removed_schemes_are_reported_from_a_fixed_list() {
        let values = [
            "Bearer ghp_guest",
            "BASIC eDp5",
            "token ghp_guest",
            "ghp_guest",
            "Digest username=guest",
        ]
        .map(HeaderValue::from_static);
        assert_eq!(
            AuthSchemes::of(&values).to_string(),
            "basic,bearer,token,other"
        );
        assert_eq!(AuthSchemes::of(&values[3..]).to_string(), "other");
    }

    struct Resolver;

    #[async_trait]
    impl EgressCredentialResolver for Resolver {
        async fn resolve(
            &self,
            _identity: &EgressIdentity,
            _binding_name: &str,
            _destination: &EgressDestination,
        ) -> Result<String, EgressError> {
            Ok("ghs_resolved".into())
        }
    }

    async fn rewrite(
        host: &str,
        headers: Vec<(&'static str, String)>,
    ) -> Result<HeaderMap, EgressError> {
        let bindings = CredentialBindings::new(
            vec![EgressCredentialBinding {
                name: "github".into(),
                environment_variable: "GH_TOKEN".into(),
                networking: CredentialNetworkPolicy::Limited {
                    allowed_hosts: vec!["api.test".into()],
                },
                injection_location: CredentialInjectionLocation { header: true },
            }],
            Some(&HashMap::from([("GH_TOKEN".into(), PLACEHOLDER.into())])),
        )?;
        let identity = EgressIdentity {
            sandbox_id: "hosted".into(),
            scope: crate::ResourceScope::Global,
        };
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(
                name,
                HeaderValue::from_str(&value).map_err(anyhow::Error::from)?,
            );
        }
        bindings
            .rewrite_headers(
                &mut map,
                &destination(host, "/repos/org/repo/pulls"),
                true,
                &identity,
                &Resolver,
            )
            .await?;
        Ok(map)
    }

    #[tokio::test]
    async fn hosted_rewrite_strips_before_substitution_and_keeps_rejections() -> Result<()> {
        let headers = rewrite(
            "api.test",
            vec![
                ("authorization", "token ghp_guest".into()),
                ("cookie", "user_session=guest".into()),
                ("x-github-api-version", "2022-11-28".into()),
            ],
        )
        .await?;
        assert!(!headers.contains_key(AUTHORIZATION));
        assert!(!headers.contains_key(COOKIE));
        assert_eq!(headers["x-github-api-version"], "2022-11-28");
        let headers = rewrite(
            "api.test",
            vec![(
                "authorization",
                basic(&format!("x-access-token:{PLACEHOLDER}")),
            )],
        )
        .await?;
        assert_eq!(
            headers[AUTHORIZATION],
            basic("x-access-token:ghs_resolved").as_str()
        );
        let headers = rewrite(
            "public.test",
            vec![
                ("authorization", "token ghp_guest".into()),
                ("cookie", "user_session=guest".into()),
            ],
        )
        .await?;
        assert_eq!(headers[AUTHORIZATION], "token ghp_guest");
        assert_eq!(headers[COOKIE], "user_session=guest");
        for headers in [
            vec![("authorization", format!("Bearer {OTHER_PLACEHOLDER}"))],
            vec![
                ("authorization", format!("Bearer {PLACEHOLDER}")),
                ("authorization", "Bearer ghp_guest".into()),
            ],
        ] {
            assert!(matches!(
                rewrite("api.test", headers).await,
                Err(EgressError::Denied(_))
            ));
        }
        Ok(())
    }
}
