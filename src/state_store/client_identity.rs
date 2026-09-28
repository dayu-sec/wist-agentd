//! Agent 本地身份材料：客户端密钥对、CSR 与已签发的客户端证书（mTLS）。
//!
//! 设计：`wist-gateway/docs/design/agent-identity-mtls.md` §4.2 / §5.4。三条口径：
//!
//! - 私钥**本地生成、不出本机**（0600），只把 **CSR** 交上去；
//! - CSR **只贡献公钥**，主体（URI SAN）由网关按稳定哈希 `agent_id` 填 —— 这里不做任何主体声明；
//! - 「过期」由 **agent 本地读 `notAfter` 自检**：服务端在握手期就拒过期证书，HTTP 层给不出错误码。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, KeyPair};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use x509_parser::prelude::{FromDer, X509Certificate};

/// 本地客户端私钥（相对 state 目录）。
pub const CLIENT_KEY_RELATIVE_PATH: &str = "identity/client.key.pem";
/// 网关签发的客户端证书（相对 state 目录）。
pub const CLIENT_CERT_RELATIVE_PATH: &str = "identity/client.crt.pem";

/// 续期提前量：证书 37 天、保底 30 天 → 剩余 ≤ 30 天就该续（§4.2）。
pub const RENEWAL_LEAD_SECONDS: i64 = 30 * 24 * 60 * 60;

/// 本地身份材料的路径（都在 state 目录下）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentityPaths {
    pub key_file: PathBuf,
    pub cert_file: PathBuf,
}

impl ClientIdentityPaths {
    pub fn under(state_dir: &Path) -> Self {
        Self {
            key_file: state_dir.join(CLIENT_KEY_RELATIVE_PATH),
            cert_file: state_dir.join(CLIENT_CERT_RELATIVE_PATH),
        }
    }
}

/// 载入本地私钥；没有就生成一把并落盘（0600）。
pub fn load_or_generate_key_pair(paths: &ClientIdentityPaths) -> io::Result<KeyPair> {
    if paths.key_file.exists() {
        let pem = fs::read_to_string(&paths.key_file)?;
        return KeyPair::from_pem(&pem).map_err(|err| {
            invalid_data(format!(
                "failed to parse local client key {}: {err}",
                paths.key_file.display()
            ))
        });
    }
    let key_pair = KeyPair::generate()
        .map_err(|err| io::Error::other(format!("failed to generate local client key: {err}")))?;
    write_private(&paths.key_file, key_pair.serialize_pem().as_bytes())?;
    Ok(key_pair)
}

/// 用本地私钥生成 CSR（PEM）。主体留空 —— 由网关按稳定哈希 `agent_id` 填（§4.2）。
pub fn build_certificate_signing_request(key_pair: &KeyPair) -> io::Result<String> {
    CertificateParams::default()
        .serialize_request(key_pair)
        .and_then(|csr| csr.pem())
        .map_err(|err| {
            io::Error::other(format!(
                "failed to build certificate signing request: {err}"
            ))
        })
}

/// 落盘网关签发的客户端证书（0600）。
pub fn store_client_certificate(
    paths: &ClientIdentityPaths,
    certificate_pem: &str,
) -> io::Result<()> {
    write_private(&paths.cert_file, certificate_pem.as_bytes())
}

/// 本地证书的有效期状态（§5.4：过期由 agent 本地判定，不靠服务端错误码）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateValidity {
    /// 剩余还多，不用管。
    Valid,
    /// 落在续期窗内（剩余 ≤ [`RENEWAL_LEAD_SECONDS`]）→ 该续签（§4.2）。
    RenewDue,
    /// 已过期 → 需带 token 重装（§4.2 无宽限）。
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificateStatus {
    pub not_after: String,
    pub remaining_seconds: i64,
    pub validity: CertificateValidity,
}

/// 读回本地客户端证书 PEM；还没注册时是 `None`。
pub fn read_client_certificate(paths: &ClientIdentityPaths) -> io::Result<Option<String>> {
    read_optional(&paths.cert_file)
}

/// 读回本地私钥 PEM；还没生成时是 `None`。
pub fn read_client_private_key_pem(paths: &ClientIdentityPaths) -> io::Result<Option<String>> {
    read_optional(&paths.key_file)
}

/// 拼成「证书 + 私钥」**单份 PEM** —— reqwest / rustls 出示客户端身份要的就是这一份。
///
/// 两者缺一返回 `None`（还没注册，没什么可出示的）。
pub fn combined_client_identity_pem(paths: &ClientIdentityPaths) -> io::Result<Option<String>> {
    let Some(certificate) = read_client_certificate(paths)? else {
        return Ok(None);
    };
    let Some(key) = read_client_private_key_pem(paths)? else {
        return Ok(None);
    };
    Ok(Some(format!(
        "{}\n{}",
        certificate.trim_end_matches('\n'),
        key
    )))
}

fn read_optional(path: &Path) -> io::Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    fs::read_to_string(path).map(Some)
}

/// 读本地证书的有效期状态；还没有证书（未注册）→ `Ok(None)`。
pub fn client_certificate_status(
    paths: &ClientIdentityPaths,
) -> io::Result<Option<ClientCertificateStatus>> {
    let Some(pem) = read_client_certificate(paths)? else {
        return Ok(None);
    };
    certificate_status_from_pem(&pem, OffsetDateTime::now_utc().unix_timestamp()).map(Some)
}

/// 从 PEM 读出 `notAfter` 并按给定时刻判定（时刻参数化，便于测试）。
fn certificate_status_from_pem(
    certificate_pem: &str,
    now_unix: i64,
) -> io::Result<ClientCertificateStatus> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).map_err(|err| {
        invalid_data(format!(
            "failed to parse local client certificate PEM: {err:?}"
        ))
    })?;
    let (_, certificate) = X509Certificate::from_der(&pem.contents)
        .map_err(|err| invalid_data(format!("failed to parse local client certificate: {err}")))?;
    let not_after_unix = certificate.validity().not_after.timestamp();
    let remaining_seconds = not_after_unix - now_unix;
    let validity = if remaining_seconds <= 0 {
        CertificateValidity::Expired
    } else if remaining_seconds <= RENEWAL_LEAD_SECONDS {
        CertificateValidity::RenewDue
    } else {
        CertificateValidity::Valid
    };
    Ok(ClientCertificateStatus {
        not_after: format_rfc3339(not_after_unix),
        remaining_seconds,
        validity,
    })
}

fn format_rfc3339(unix_seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix_seconds)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
        .unwrap_or_else(|| unix_seconds.to_string())
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_state_dir() -> PathBuf {
        static NEXT_SUFFIX: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!(
            "wist-agentd-identity-{}-{}",
            std::process::id(),
            NEXT_SUFFIX.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("temp state dir");
        dir
    }

    /// 造一张自签证书，有效期在 `[now + not_before_days, now + not_after_days]`。
    fn certificate_pem(not_before_days: i64, not_after_days: i64) -> String {
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        params.not_before = now + time::Duration::days(not_before_days);
        params.not_after = now + time::Duration::days(not_after_days);
        let key = KeyPair::generate().expect("key");
        params.self_signed(&key).expect("self signed").pem()
    }

    #[test]
    fn generates_key_pair_once_and_keeps_it_private() {
        let dir = temp_state_dir();
        let paths = ClientIdentityPaths::under(&dir);

        let first = load_or_generate_key_pair(&paths).expect("generate");
        assert!(paths.key_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&paths.key_file)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "private key must not be world readable");
        }

        let second = load_or_generate_key_pair(&paths).expect("reload");
        assert_eq!(
            first.public_key_der(),
            second.public_key_der(),
            "second call must reuse the on-disk key"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn builds_a_certificate_signing_request() {
        let key = KeyPair::generate().expect("key");
        let csr = build_certificate_signing_request(&key).expect("csr");
        assert!(csr.contains("-----BEGIN CERTIFICATE REQUEST-----"), "{csr}");
    }

    #[test]
    fn detects_valid_renew_due_and_expired() {
        let now = OffsetDateTime::now_utc().unix_timestamp();

        let valid = certificate_status_from_pem(&certificate_pem(-1, 37), now).expect("status");
        assert_eq!(valid.validity, CertificateValidity::Valid);
        assert!(valid.remaining_seconds > RENEWAL_LEAD_SECONDS);

        let renew_due = certificate_status_from_pem(&certificate_pem(-1, 10), now).expect("status");
        assert_eq!(renew_due.validity, CertificateValidity::RenewDue);
        assert!(renew_due.remaining_seconds > 0);

        let expired = certificate_status_from_pem(&certificate_pem(-40, -1), now).expect("status");
        assert_eq!(expired.validity, CertificateValidity::Expired);
        assert!(expired.remaining_seconds < 0);
    }

    #[test]
    fn reports_no_certificate_before_enrollment() {
        let dir = temp_state_dir();
        let paths = ClientIdentityPaths::under(&dir);
        assert!(
            client_certificate_status(&paths).expect("status").is_none(),
            "no certificate yet"
        );

        store_client_certificate(&paths, &certificate_pem(-1, 37)).expect("store");
        let status = client_certificate_status(&paths)
            .expect("status")
            .expect("stored certificate");
        assert_eq!(status.validity, CertificateValidity::Valid);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn combines_certificate_and_key_into_a_single_identity_pem() {
        let dir = temp_state_dir();
        let paths = ClientIdentityPaths::under(&dir);
        assert!(
            combined_client_identity_pem(&paths)
                .expect("read")
                .is_none(),
            "nothing to present yet"
        );

        load_or_generate_key_pair(&paths).expect("key");
        assert!(
            combined_client_identity_pem(&paths)
                .expect("read")
                .is_none(),
            "key alone is not an identity"
        );

        store_client_certificate(&paths, &certificate_pem(-1, 37)).expect("store");
        let combined = combined_client_identity_pem(&paths)
            .expect("read")
            .expect("combined identity");
        assert!(combined.contains("BEGIN CERTIFICATE"), "{combined}");
        assert!(combined.contains("BEGIN PRIVATE KEY"), "{combined}");
        let _ = fs::remove_dir_all(dir);
    }
}
