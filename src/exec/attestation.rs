//! 计划签发证明（`ActionPlanAttestation`）的**本地验签**。
//!
//! 被管端只做两件事：**算摘要**、**验签名**。它不审批、不签发，也不需要知道审批怎么走 ——
//! 那两件事属于控制面。这里唯一的信任输入是本地配置里的**公钥**（钉死在机器上）。
//!
//! 三条刻意的取舍：
//!
//! 1. **公钥只能来自本地文件**（绝对路径）。绝不「每次向网关要公钥」：那等于让被控方
//!    自己决定信任谁，验签就退化成装饰。
//! 2. **不做多算法协商**。`algorithm` 不是 `ed25519` 就是拒 —— 算法协商是最经典的降级面。
//! 3. **验签失败不区分「签名错」和「密钥不对」**（对外同一个 `signature_invalid`）：
//!    这两者的区别只对攻击者有用。
//!
//! PEM 解析与验签实现与 `wist-gateway/src/infra/ed25519.rs` 同源，但**刻意各留一份**：
//! 被管端不依赖控制面的代码（那是它要逆反的信任边界）。两边的测试各自钉住自己的实现。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::config::agent_config::AttestationSection;

/// Ed25519 SPKI DER 的固定前缀（后跟 32 字节裸公钥）。
const ED25519_PUBLIC_KEY_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// 公钥 PEM 的大小上限。一个 Ed25519 SPKI 公钥只有 113 字节；8 KiB 已经宽得离谱。
/// 加它是为了不让一份被换成几个 G 的“公钥文件”把 agentd 读死。
const MAX_PUBLIC_KEY_PEM_BYTES: u64 = 8 * 1024;

/// 验签/加载信任锚的失败。`code` 与 `plan_review::Rejection` 同一套词表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationFailure {
    pub code: &'static str,
    pub detail: String,
}

impl AttestationFailure {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// 本地信任锚：`key_id -> 裸公钥`。
///
/// 一个 `key_id` 一把钥匙是**故意的**：轮换期两把并存（旧计划还能验），
/// 但计划里声明的 `key_id` 必须命中其中一把，否则换锚时旧计划会被静默接受。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedKeys {
    keys: BTreeMap<String, Vec<u8>>,
}

impl TrustedKeys {
    /// 从配置段加载。任一文件读不到 / 不是 Ed25519 SPKI PEM → 整体失败（fail-closed）。
    ///
    /// **每次 review 都重新读文件**，是有意的：换公钥不需要重启 agentd，
    /// 下一份计划就按新锚验。代价是一次磁盘读 —— 与一条响应的其余开销相比可忽略。
    pub fn from_section(section: &AttestationSection) -> Result<Self, AttestationFailure> {
        let mut keys = BTreeMap::new();
        for entry in &section.trusted_keys {
            let key_id = entry.key_id.trim();
            if key_id.is_empty() {
                return Err(AttestationFailure::new(
                    crate::exec::opcode::codes::ATTESTATION_KEY_INVALID,
                    "attestation.trusted_keys 里的 key_id 不能为空",
                ));
            }
            if keys.contains_key(key_id) {
                return Err(AttestationFailure::new(
                    crate::exec::opcode::codes::ATTESTATION_KEY_INVALID,
                    format!("attestation.trusted_keys 里的 key_id {key_id} 重复"),
                ));
            }
            let path = Path::new(entry.public_key_pem_file.trim());
            if !path.is_absolute() {
                return Err(AttestationFailure::new(
                    crate::exec::opcode::codes::ATTESTATION_KEY_INVALID,
                    format!(
                        "attestation.trusted_keys[{key_id}].public_key_pem_file 必须是绝对路径：{}",
                        path.display()
                    ),
                ));
            }
            let metadata = std::fs::metadata(path).map_err(|err| {
                AttestationFailure::new(
                    crate::exec::opcode::codes::ATTESTATION_KEY_UNAVAILABLE,
                    format!("读取公钥 {} 失败：{err}", path.display()),
                )
            })?;
            if metadata.len() > MAX_PUBLIC_KEY_PEM_BYTES {
                return Err(AttestationFailure::new(
                    crate::exec::opcode::codes::ATTESTATION_KEY_INVALID,
                    format!(
                        "公钥 {} 太大（{} 字节，上限 {MAX_PUBLIC_KEY_PEM_BYTES}）",
                        path.display(),
                        metadata.len()
                    ),
                ));
            }
            let pem = std::fs::read_to_string(path).map_err(|err| {
                AttestationFailure::new(
                    crate::exec::opcode::codes::ATTESTATION_KEY_UNAVAILABLE,
                    format!("读取公钥 {} 失败：{err}", path.display()),
                )
            })?;
            let raw = parse_ed25519_public_key_pem(&pem).map_err(|err| {
                AttestationFailure::new(
                    crate::exec::opcode::codes::ATTESTATION_KEY_INVALID,
                    format!("公钥 {} 不是合法的 Ed25519 SPKI PEM：{err}", path.display()),
                )
            })?;
            keys.insert(key_id.to_string(), raw);
        }
        Ok(Self { keys })
    }

    pub fn get(&self, key_id: &str) -> Option<&[u8]> {
        self.keys.get(key_id).map(Vec::as_slice)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// 声明的 key_id 集合（诊断用：告诉运维「本机到底信哪几把」）。
    pub fn key_ids(&self) -> BTreeSet<&str> {
        self.keys.keys().map(String::as_str).collect()
    }
}

/// 验签。签名格式错了、密钥不对、被改过一个字节，都返回 `false`。
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

/// 解析 Ed25519 **公钥** PEM（SPKI）。
pub fn parse_ed25519_public_key_pem(pem: &str) -> Result<Vec<u8>, String> {
    const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
    const END: &str = "-----END PUBLIC KEY-----";
    let begin = pem.find(BEGIN).ok_or_else(|| {
        "public key must be an SPKI PEM (`-----BEGIN PUBLIC KEY-----`)".to_string()
    })?;
    let rest = &pem[begin + BEGIN.len()..];
    let end = rest
        .find(END)
        .ok_or_else(|| "public key PEM is missing its footer".to_string())?;
    let body: String = rest[..end]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err("public key PEM body is empty".to_string());
    }
    let der = STANDARD
        .decode(body)
        .map_err(|err| format!("failed to decode public key PEM: {err}"))?;
    let Some(raw) = der.strip_prefix(ED25519_PUBLIC_KEY_SPKI_PREFIX.as_slice()) else {
        return Err("public key is not an Ed25519 SPKI key".to_string());
    };
    if raw.len() != 32 {
        return Err(format!(
            "Ed25519 public key must be 32 bytes, found {}",
            raw.len()
        ));
    }
    Ok(raw.to_vec())
}

/// 小写/大写 hex → 字节。长度奇数或含非 hex 字符返回 `None`。
pub fn hex_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let hi = (bytes[index] as char).to_digit(16)?;
        let lo = (bytes[index + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        index += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519_public_key_pem(public_key: &[u8]) -> String {
        let mut der = Vec::with_capacity(ED25519_PUBLIC_KEY_SPKI_PREFIX.len() + public_key.len());
        der.extend_from_slice(&ED25519_PUBLIC_KEY_SPKI_PREFIX);
        der.extend_from_slice(public_key);
        let encoded = STANDARD.encode(&der);
        let mut wrapped = String::new();
        for chunk in encoded.as_bytes().chunks(64) {
            wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            wrapped.push('\n');
        }
        format!("-----BEGIN PUBLIC KEY-----\n{wrapped}-----END PUBLIC KEY-----\n")
    }

    #[test]
    fn public_key_pem_round_trips() {
        let raw = [7u8; 32];
        let pem = ed25519_public_key_pem(&raw);
        assert_eq!(
            parse_ed25519_public_key_pem(&pem).expect("parse"),
            raw.to_vec()
        );
    }

    #[test]
    fn rejects_pem_that_is_not_an_ed25519_spki_key() {
        let mut der = Vec::new();
        der.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x01]);
        let encoded = STANDARD.encode(&der);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{encoded}\n-----END PUBLIC KEY-----\n");
        let err = parse_ed25519_public_key_pem(&pem).expect_err("must refuse");
        assert!(err.contains("not an Ed25519"), "{err}");

        let err = parse_ed25519_public_key_pem("not a pem").expect_err("must refuse");
        assert!(err.contains("SPKI PEM"), "{err}");
    }

    #[test]
    fn verifies_only_the_matching_signature() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
        let public = key_pair.public_key().as_ref().to_vec();
        let message = b"plan-v1:sha256:deadbeef";
        let signature = key_pair.sign(message).as_ref().to_vec();
        assert!(verify_ed25519(&public, message, &signature));
        assert!(!verify_ed25519(
            &public,
            b"plan-v1:sha256:deadbeee",
            &signature
        ));

        let mut other = public.clone();
        other[0] ^= 0x01;
        assert!(!verify_ed25519(&other, message, &signature));
    }

    #[test]
    fn hex_decode_round_trips_and_rejects_odd_input() {
        assert_eq!(hex_decode("00ff10").expect("hex"), vec![0, 255, 16]);
        assert_eq!(hex_decode("AB").expect("hex"), vec![0xab]);
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn trusted_keys_refuse_empty_and_relative_paths() {
        let section = AttestationSection {
            enforced: true,
            trusted_keys: vec![crate::config::agent_config::AttestationKeySection {
                key_id: " ".to_string(),
                public_key_pem_file: "/tmp/x.pem".to_string(),
            }],
        };
        let err = TrustedKeys::from_section(&section).expect_err("empty key id");
        assert_eq!(
            err.code,
            crate::exec::opcode::codes::ATTESTATION_KEY_INVALID
        );

        let section = AttestationSection {
            enforced: true,
            trusted_keys: vec![crate::config::agent_config::AttestationKeySection {
                key_id: "k1".to_string(),
                public_key_pem_file: "relative.pem".to_string(),
            }],
        };
        let err = TrustedKeys::from_section(&section).expect_err("relative path");
        assert_eq!(
            err.code,
            crate::exec::opcode::codes::ATTESTATION_KEY_INVALID
        );
    }

    #[test]
    fn an_oversized_public_key_file_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "wist-attestation-big-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("big.pub");
        std::fs::write(&path, vec![b'A'; MAX_PUBLIC_KEY_PEM_BYTES as usize + 1]).expect("write");

        let section = AttestationSection {
            enforced: true,
            trusted_keys: vec![crate::config::agent_config::AttestationKeySection {
                key_id: "k1".to_string(),
                public_key_pem_file: path.display().to_string(),
            }],
        };
        let err = TrustedKeys::from_section(&section).expect_err("oversized");
        assert_eq!(
            err.code,
            crate::exec::opcode::codes::ATTESTATION_KEY_INVALID
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trusted_keys_load_a_real_file() {
        let dir = std::env::temp_dir().join(format!("wist-attestation-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("k1.pub");
        let pem = ed25519_public_key_pem(&[9u8; 32]);
        std::fs::write(&path, pem).expect("write");

        let section = AttestationSection {
            enforced: true,
            trusted_keys: vec![crate::config::agent_config::AttestationKeySection {
                key_id: "k1".to_string(),
                public_key_pem_file: path.display().to_string(),
            }],
        };
        let keys = TrustedKeys::from_section(&section).expect("load");
        assert_eq!(keys.get("k1"), Some([9u8; 32].as_slice()));
        assert!(keys.get("k2").is_none());
        assert!(!keys.is_empty());
        assert_eq!(keys.key_ids().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
