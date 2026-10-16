/**
 * ML-DSA-65 agent keys and the on-disk keystore.
 *
 * Byte-identical to the Rust SDK (`sdk/src/keys.rs`) and the zk-batch guest:
 *  - key = FIPS 204 ML-DSA-65 KeyGen from a 32-byte seed (@noble/post-quantum `ml_dsa65.keygen(seed)`
 *    == RustCrypto `ml-dsa` `SigningKey::from_seed`)
 *  - pkHash = sha256(encoded verifying key, 1952 B)  (what AgentRegistry stores and the guest checks)
 *  - signatures = FIPS 204 *deterministic* ML-DSA-65 (rnd = 0^32), empty context, 3309 B
 *  - key.json = the Rust keystore format (plain seed protected by 0600, or Argon2id + ChaCha20-Poly1305),
 *    so a `.pqagent/` directory created by either SDK works with the other.
 *
 * The secret seed lives in a private class field and is never returned, logged or serialised:
 * `JSON.stringify(key)` and `console.log(key)` only show the pkHash.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from 'node:crypto';
import { promises as fs, constants as fsc } from 'node:fs';
import { inspect } from 'node:util';
import { concat, hex0x, unhex, type Hex } from './bytes.js';

export const PUBLIC_KEY_LEN = 1952;
export const SIGNATURE_LEN = 3309;
/** Env var holding the keystore passphrase (same as the Rust CLI). */
export const PASSPHRASE_ENV = 'PQAGENT_PASSPHRASE';
/** Rust `argon2::Argon2::default()`: Argon2id v0x13, m = 19456 KiB, t = 2, p = 1, 32-byte output. */
export const KDF_ID = 'argon2id(v19,m=19456,t=2,p=1)';
const ARGON = { t: 2, m: 19456, p: 1, dkLen: 32, version: 0x13 } as const;

export class AgentKey {
  readonly #seed: Uint8Array;
  readonly #secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly pkHash: Uint8Array;

  private constructor(seed: Uint8Array) {
    if (seed.length !== 32) throw new Error('ML-DSA-65 seed must be 32 bytes');
    this.#seed = Uint8Array.from(seed);
    const { secretKey, publicKey } = ml_dsa65.keygen(this.#seed);
    this.#secretKey = secretKey;
    this.publicKey = publicKey;
    this.pkHash = pkHash(publicKey);
  }

  /** Fresh key from the OS CSPRNG. */
  static generate(): AgentKey {
    const s = new Uint8Array(randomBytes(32));
    try { return new AgentKey(s); } finally { s.fill(0); }
  }

  static fromSeed(seed: Uint8Array): AgentKey {
    return new AgentKey(seed);
  }

  /**
   * The repo's deterministic TEST keys (agents 1 and 2 in every proved fixture):
   * seed = keccak256("EmpowerTours test agent seed " || i). PUBLIC — never use for real funds.
   */
  static testKey(i: number): AgentKey {
    return new AgentKey(keccak_256(concat(new TextEncoder().encode('EmpowerTours test agent seed '), Uint8Array.of(i))));
  }

  get pkHashHex(): Hex { return hex0x(this.pkHash); }

  /** FIPS 204 deterministic ML-DSA-65 signature, empty context (what the guest verifies). */
  sign(msg: Uint8Array): Uint8Array {
    return ml_dsa65.sign(msg, this.#secretKey, { extraEntropy: false });
  }

  /** Hedged (randomised) FIPS 204 signature. Also valid for the guest; not reproducible. */
  signRandomized(msg: Uint8Array): Uint8Array {
    return ml_dsa65.sign(msg, this.#secretKey);
  }

  /** @internal keystore only */
  _seedForKeystore(): Uint8Array { return this.#seed; }

  /** Overwrite the in-memory secret material (best effort; JS cannot guarantee no copies remain). */
  destroy(): void { this.#seed.fill(0); this.#secretKey.fill(0); }

  toJSON() { return { algorithm: 'ML-DSA-65', pkHash: this.pkHashHex }; }
  [inspect.custom]() { return `AgentKey(ML-DSA-65, pkHash ${this.pkHashHex})`; }
  toString() { return `AgentKey(ML-DSA-65, pkHash ${this.pkHashHex})`; }
}

/** sha256 of the encoded ML-DSA-65 verifying key (== guest group_key check == registry pkHash). */
export function pkHash(publicKey: Uint8Array): Uint8Array {
  return sha256(publicKey);
}

/** Model hash committed in every signed action: keccak256 of the model artifact (file bytes or UTF-8 string). */
export function modelHash(artifact: Uint8Array | string): Uint8Array {
  return keccak_256(typeof artifact === 'string' ? new TextEncoder().encode(artifact) : artifact);
}

/** Verify an ML-DSA-65 signature exactly as the guest does (FIPS 204, empty context). */
export function verifySignature(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (publicKey.length !== PUBLIC_KEY_LEN || sig.length !== SIGNATURE_LEN) return false;
  try { return ml_dsa65.verify(sig, msg, publicKey); } catch { return false; }
}

// ---------------------------------------------------------------- keystore (Rust-compatible key.json)

export interface KeyFile {
  version: 1;
  algorithm: string;
  pkHash: Hex;
  encrypted: boolean;
  seed?: string;
  kdf?: string;
  salt?: string;
  nonce?: string;
  ciphertext?: string;
}

async function kek(pass: string, salt: Uint8Array): Promise<Uint8Array> {
  return argon2idAsync(new TextEncoder().encode(pass), salt, ARGON);
}

/** Create `dir` with mode 0700 (and tighten it if it already exists). */
export async function ensurePrivateDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') await fs.chmod(dir, 0o700);
}

/** Write a 0600 file without ever making it group/world-readable. */
export async function writePrivate(path: string, data: string | Uint8Array): Promise<void> {
  const fh = await fs.open(path, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_TRUNC, 0o600);
  try {
    if (process.platform !== 'win32') await fh.chmod(0o600);
    await fh.writeFile(data);
  } finally { await fh.close(); }
}

/**
 * Write key.json (0600). With a passphrase the seed is sealed with ChaCha20-Poly1305 under an
 * Argon2id-derived key (same parameters as the Rust SDK); without one it is stored in hex,
 * protected only by file permissions.
 */
export async function saveKey(path: string, key: AgentKey, passphrase?: string): Promise<void> {
  const kf: KeyFile = { version: 1, algorithm: 'ML-DSA-65 (FIPS 204) seed', pkHash: key.pkHashHex, encrypted: passphrase !== undefined };
  if (passphrase === undefined) {
    kf.seed = Buffer.from(key._seedForKeystore()).toString('hex');
  } else {
    if (passphrase === '') throw new Error(`empty ${PASSPHRASE_ENV}`);
    const salt = new Uint8Array(randomBytes(16));
    const nonce = new Uint8Array(randomBytes(12));
    const k = await kek(passphrase, salt);
    const ct = chacha20poly1305(k, nonce).encrypt(key._seedForKeystore());
    k.fill(0);
    Object.assign(kf, { kdf: KDF_ID, salt: hex(salt), nonce: hex(nonce), ciphertext: hex(ct) });
  }
  await writePrivate(path, JSON.stringify(kf, null, 2) + '\n');
}

function hex(b: Uint8Array) { return Buffer.from(b).toString('hex'); }

/** Load key.json written by either SDK. Refuses group/world-readable files (like the Rust CLI). */
export async function loadKey(path: string, passphrase?: string): Promise<AgentKey> {
  if (process.platform !== 'win32') {
    const mode = (await fs.stat(path)).mode;
    if (mode & 0o077) throw new Error(`${path} is accessible by group/others (mode ${(mode & 0o777).toString(8)}); run: chmod 600 ${path}`);
  }
  const kf = JSON.parse(await fs.readFile(path, 'utf8')) as KeyFile;
  let seed: Uint8Array;
  if (kf.encrypted) {
    if (passphrase === undefined) throw new Error(`key is encrypted: set ${PASSPHRASE_ENV}`);
    if (kf.kdf && kf.kdf !== KDF_ID) throw new Error(`unsupported kdf ${kf.kdf}`);
    const nonce = unhex(kf.nonce ?? '');
    if (nonce.length !== 12) throw new Error('bad nonce');
    const k = await kek(passphrase, unhex(kf.salt ?? ''));
    try { seed = chacha20poly1305(k, nonce).decrypt(unhex(kf.ciphertext ?? '')); }
    catch { throw new Error(`wrong ${PASSPHRASE_ENV} or corrupted key.json`); }
    finally { k.fill(0); }
  } else {
    if (!kf.seed) throw new Error('key.json: no seed');
    seed = unhex(kf.seed);
  }
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  const key = AgentKey.fromSeed(seed);
  seed.fill(0);
  if (key.pkHashHex !== kf.pkHash.toLowerCase()) throw new Error('key.json pkHash mismatch (file corrupted?)');
  return key;
}
