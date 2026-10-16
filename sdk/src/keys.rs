//! ML-DSA-65 agent keys and the on-disk keystore.
//!
//! Key derivation, public-key encoding and signing are byte-identical to the zk-batch host
//! (`ml-dsa = 0.1.1`, `SigningKey::from_seed`, FIPS 204 deterministic signing, empty context), so
//! anything signed here verifies inside the SP1 guest. `pkHash = sha256(encoded verifying key)` is
//! what the guest checks and what `AgentRegistry` stores.

use alloy_primitives::keccak256;
use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ml_dsa::{MlDsa65, SigningKey, B32};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

pub const PUBLIC_KEY_LEN: usize = 1952;
pub const SIGNATURE_LEN: usize = 3309;
/// Env var holding the keystore passphrase. When set at `init`, the seed is encrypted.
pub const PASSPHRASE_ENV: &str = "PQAGENT_PASSPHRASE";

/// An ML-DSA-65 agent key. Holds the 32-byte FIPS 204 seed (zeroized on drop) and the expanded key.
pub struct AgentKey {
    seed: Zeroizing<[u8; 32]>,
    sk: SigningKey<MlDsa65>,
    pk: Vec<u8>,
}

impl AgentKey {
    /// Fresh key from the OS RNG.
    pub fn generate() -> Result<Self> {
        let mut s = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(s.as_mut()).map_err(|e| anyhow!("os rng: {e}"))?;
        Ok(Self::from_seed(*s))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sk = SigningKey::<MlDsa65>::from_seed(&B32::from(seed));
        let pk = sk.expanded_key().verifying_key().encode().to_vec();
        Self { seed: Zeroizing::new(seed), sk, pk }
    }

    /// The repo's deterministic TEST keys (agents 1 and 2 in every proved fixture):
    /// seed = keccak256("EmpowerTours test agent seed " || i). PUBLIC — never use for real funds.
    pub fn test_key(i: u8) -> Self {
        Self::from_seed(keccak256([b"EmpowerTours test agent seed ".as_slice(), &[i]].concat()).0)
    }

    pub fn public_key(&self) -> &[u8] {
        &self.pk
    }

    pub fn pk_hash(&self) -> [u8; 32] {
        pk_hash(&self.pk)
    }

    /// FIPS 204 deterministic ML-DSA-65 signature with an empty context (what the guest verifies).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sk.expanded_key().sign_deterministic(msg, &[]).expect("empty ctx").encode().to_vec()
    }

    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

/// sha256 of the encoded ML-DSA-65 verifying key (== guest `group_key` check == registry pkHash).
pub fn pk_hash(pk: &[u8]) -> [u8; 32] {
    Sha256::digest(pk).into()
}

/// Model hash committed in every signed action: keccak256 of the model artifact (file bytes or string).
pub fn model_hash(bytes: &[u8]) -> [u8; 32] {
    keccak256(bytes).0
}

/// Verify an ML-DSA-65 signature exactly as the guest does.
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ml_dsa::{EncodedVerifyingKey, VerifyingKey};
    let Ok(enc) = EncodedVerifyingKey::<MlDsa65>::try_from(pk) else { return false };
    agent_batch_lib::verify_sig(&VerifyingKey::<MlDsa65>::decode(&enc), msg, sig)
}

// ---------------------------------------------------------------- keystore

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyFile {
    version: u32,
    algorithm: String,
    pk_hash: String,
    encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
}

fn kek(pass: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut k = Zeroizing::new([0u8; 32]);
    Argon2::default().hash_password_into(pass.as_bytes(), salt, k.as_mut()).map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(k)
}

/// Create `dir` (0700) and write a 0600 file without ever making it world-readable.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)
            .with_context(|| format!("open {}", path.display()))?;
        f.write_all(data)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    fs::write(path, data)?;
    Ok(())
}

pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `key.json` (0600). With a passphrase the seed is sealed with ChaCha20-Poly1305 under an
/// Argon2id-derived key; without one it is stored in hex, protected only by file permissions.
pub fn save_key(path: &Path, key: &AgentKey, passphrase: Option<&str>) -> Result<()> {
    let mut kf = KeyFile {
        version: 1,
        algorithm: "ML-DSA-65 (FIPS 204) seed".into(),
        pk_hash: format!("0x{}", hex::encode(key.pk_hash())),
        encrypted: passphrase.is_some(),
        seed: None, kdf: None, salt: None, nonce: None, ciphertext: None,
    };
    match passphrase {
        None => kf.seed = Some(hex::encode(key.seed())),
        Some(p) => {
            if p.is_empty() { bail!("empty {PASSPHRASE_ENV}") }
            let mut salt = [0u8; 16];
            let mut nonce = [0u8; 12];
            getrandom::getrandom(&mut salt).map_err(|e| anyhow!("{e}"))?;
            getrandom::getrandom(&mut nonce).map_err(|e| anyhow!("{e}"))?;
            let k = kek(p, &salt)?;
            let ct = ChaCha20Poly1305::new(k.as_ref().into())
                .encrypt(Nonce::from_slice(&nonce), key.seed().as_slice())
                .map_err(|_| anyhow!("encrypt"))?;
            kf.kdf = Some("argon2id(v19,m=19456,t=2,p=1)".into());
            kf.salt = Some(hex::encode(salt));
            kf.nonce = Some(hex::encode(nonce));
            kf.ciphertext = Some(hex::encode(ct));
        }
    }
    let mut out = Zeroizing::new(serde_json::to_vec_pretty(&kf)?);
    out.push(b'\n');
    write_private(path, &out)
}

pub fn load_key(path: &Path, passphrase: Option<&str>) -> Result<AgentKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).with_context(|| format!("read {}", path.display()))?.permissions().mode();
        if mode & 0o077 != 0 {
            bail!("{} is accessible by group/others (mode {:o}); run: chmod 600 {}", path.display(), mode & 0o777, path.display());
        }
    }
    let raw = Zeroizing::new(fs::read(path).with_context(|| format!("read {}", path.display()))?);
    let kf: KeyFile = serde_json::from_slice(&raw).context("parse key.json")?;
    let seed: Zeroizing<Vec<u8>> = if kf.encrypted {
        let p = passphrase.ok_or_else(|| anyhow!("key is encrypted: set {PASSPHRASE_ENV}"))?;
        let salt = hex::decode(kf.salt.as_deref().unwrap_or_default())?;
        let nonce = hex::decode(kf.nonce.as_deref().unwrap_or_default())?;
        let ct = hex::decode(kf.ciphertext.as_deref().unwrap_or_default())?;
        if nonce.len() != 12 { bail!("bad nonce") }
        let k = kek(p, &salt)?;
        Zeroizing::new(ChaCha20Poly1305::new(k.as_ref().into()).decrypt(Nonce::from_slice(&nonce), ct.as_slice())
            .map_err(|_| anyhow!("wrong {PASSPHRASE_ENV} or corrupted key.json"))?)
    } else {
        Zeroizing::new(hex::decode(kf.seed.as_deref().ok_or_else(|| anyhow!("key.json: no seed"))?)?)
    };
    let s: [u8; 32] = seed.as_slice().try_into().map_err(|_| anyhow!("seed must be 32 bytes"))?;
    let key = AgentKey::from_seed(s);
    let want = format!("0x{}", hex::encode(key.pk_hash()));
    if want != kf.pk_hash.to_lowercase() { bail!("key.json pkHash mismatch (file corrupted?)") }
    Ok(key)
}
