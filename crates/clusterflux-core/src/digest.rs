use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Digest(String);

impl Digest {
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes.as_ref());
        Self(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    pub fn from_parts(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            let part = part.as_ref();
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        Self(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    pub fn from_sha256_hex(hex_digest: impl Into<String>) -> Result<Self, String> {
        let digest = Self(format!("sha256:{}", hex_digest.into()));
        if digest.is_valid_sha256() {
            Ok(digest)
        } else {
            Err(
                "SHA-256 digest must contain exactly 64 lowercase hexadecimal characters"
                    .to_owned(),
            )
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid_sha256(&self) -> bool {
        let Some(hex) = self.0.strip_prefix("sha256:") else {
            return false;
        };
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_validates_strict_sha256_syntax() {
        assert!(Digest::sha256("bytes").is_valid_sha256());
        assert!(!Digest("sha1:abc".to_owned()).is_valid_sha256());
        assert!(!Digest("sha256:ABCDEF".to_owned()).is_valid_sha256());
        assert!(!Digest("sha256:not-hex".to_owned()).is_valid_sha256());
    }
}
