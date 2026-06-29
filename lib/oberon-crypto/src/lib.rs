// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Thin Rust wrapper over the nRF Oberon (`ocrypto`) software crypto library --
//! a prebuilt, optimized C library for Cortex-M. We bind the algorithms the SE
//! mailbox also supports (so the two can be benchmarked head to head): AES-ECB,
//! AES-GCM, AES-CMAC, SHA-256, HMAC-SHA256, Ed25519 and X25519. The static
//! library is linked by `build.rs` (Cortex-M33 hard-float build).

#![no_std]

unsafe extern "C" {
    /// One-shot AES-ECB encrypt: `ct[0..pt_len] = AES(key)·pt`. `key`/`size` is a
    /// 16/24/32-byte AES-128/192/256 key. `pt_len` is a multiple of 16.
    fn ocrypto_aes_ecb_encrypt(
        ct: *mut u8,
        pt: *const u8,
        pt_len: usize,
        key: *const u8,
        size: usize,
    );

    /// One-shot AES-ECB decrypt (`pt = AES⁻¹(key)·ct`).
    fn ocrypto_aes_ecb_decrypt(
        pt: *mut u8,
        ct: *const u8,
        ct_len: usize,
        key: *const u8,
        size: usize,
    );

    /// One-shot AES-GCM encrypt: writes `pt_len` ciphertext bytes to `ct` and a
    /// `tag_len`-byte authentication tag to `tag`. `iv` is 12 bytes.
    fn ocrypto_aes_gcm_encrypt(
        ct: *mut u8,
        tag: *mut u8,
        tag_len: usize,
        pt: *const u8,
        pt_len: usize,
        key: *const u8,
        size: usize,
        iv: *const u8,
        aa: *const u8,
        aa_len: usize,
    );

    /// One-shot AES-CMAC: writes a `tag_len`-byte CMAC of `msg` to `tag`.
    fn ocrypto_aes_cmac_authenticate(
        tag: *mut u8,
        tag_len: usize,
        msg: *const u8,
        msg_len: usize,
        key: *const u8,
        size: usize,
    );

    /// One-shot SHA-256: writes the 32-byte digest of `in` to `r`.
    fn ocrypto_sha256(r: *mut u8, input: *const u8, in_len: usize);

    /// One-shot HMAC-SHA256: writes the 32-byte MAC of `in` under `key` to `r`.
    fn ocrypto_hmac_sha256(
        r: *mut u8,
        key: *const u8,
        key_len: usize,
        input: *const u8,
        in_len: usize,
    );

    /// Ed25519 sign: writes a 64-byte signature of `m` to `sig`, given the
    /// 32-byte secret key `sk` and 32-byte public key `pk`.
    fn ocrypto_ed25519_sign(
        sig: *mut u8,
        m: *const u8,
        m_len: usize,
        sk: *const u8,
        pk: *const u8,
    );

    /// Ed25519 verify (returns 0 on success).
    fn ocrypto_ed25519_verify(
        sig: *const u8,
        m: *const u8,
        m_len: usize,
        pk: *const u8,
    ) -> i32;

    /// Ed25519 public key from secret key.
    fn ocrypto_ed25519_public_key(pk: *mut u8, sk: *const u8);

    /// X25519 scalar multiplication `r = n·p` (Diffie-Hellman shared point).
    fn ocrypto_curve25519_scalarmult(r: *mut u8, n: *const u8, p: *const u8);

    /// X25519 base-point scalar multiplication `r = n·G` (public key).
    fn ocrypto_curve25519_scalarmult_base(r: *mut u8, n: *const u8);

    /// NIST P-256 ECDH: public key `pk` (64 B, X||Y) from secret `sk` (32 B).
    fn ocrypto_ecdh_p256_public_key(pk: *mut u8, sk: *const u8) -> i32;

    /// NIST P-256 ECDH shared secret: `r` (32 B, X-coord) = `sk`·`pk`.
    fn ocrypto_ecdh_p256_common_secret(
        r: *mut u8,
        sk: *const u8,
        pk: *const u8,
    ) -> i32;

    /// NIST P-256 ECDSA sign of a 32-byte `hash` with secret `sk` and
    /// per-signature nonce `ek`; writes a 64-byte signature (r||s).
    fn ocrypto_ecdsa_p256_sign_hash(
        sig: *mut u8,
        hash: *const u8,
        sk: *const u8,
        ek: *const u8,
    ) -> i32;

    /// NIST P-256 ECDSA verify of `sig` over `hash` with public key `pk`.
    fn ocrypto_ecdsa_p256_verify_hash(
        sig: *const u8,
        hash: *const u8,
        pk: *const u8,
    ) -> i32;

    /// ChaCha20-Poly1305 one-shot encrypt: writes ciphertext `c` and 16-byte
    /// `tag`. Arg order is tag, ciphertext, message, AAD, nonce, key.
    fn ocrypto_chacha20_poly1305_encrypt(
        tag: *mut u8,
        c: *mut u8,
        m: *const u8,
        m_len: usize,
        a: *const u8,
        a_len: usize,
        n: *const u8,
        n_len: usize,
        k: *const u8,
    );
}

unsafe extern "C" {
    /// One-shot SHA-512: writes the 64-byte digest of `in` to `r`.
    fn ocrypto_sha512(r: *mut u8, input: *const u8, in_len: usize);
    /// One-shot SHA-384: writes the 48-byte digest of `in` to `r`.
    fn ocrypto_sha384(r: *mut u8, input: *const u8, in_len: usize);
    /// One-shot AES-CTR: `ct = AES-CTR(key, iv)·pt`.
    fn ocrypto_aes_ctr_encrypt(
        ct: *mut u8,
        pt: *const u8,
        pt_len: usize,
        key: *const u8,
        size: usize,
        iv: *const u8,
    );
    /// One-shot AES-CBC encrypt.
    fn ocrypto_aes_cbc_encrypt(
        ct: *mut u8,
        pt: *const u8,
        pt_len: usize,
        key: *const u8,
        size: usize,
        iv: *const u8,
    );
    /// One-shot AES-CCM encrypt: writes ciphertext `ct` and `tag`.
    #[allow(clippy::too_many_arguments)]
    fn ocrypto_aes_ccm_encrypt(
        ct: *mut u8,
        tag: *mut u8,
        tag_len: usize,
        pt: *const u8,
        pt_len: usize,
        key: *const u8,
        size: usize,
        nonce: *const u8,
        n_len: usize,
        aa: *const u8,
        aa_len: usize,
    );
}

/// Software AES-CCM encrypt of `pt` into `ct` under `key` with a 13-byte
/// `nonce` (no AAD); writes the 16-byte `tag`.
pub fn aes_ccm_encrypt(
    key: &[u8],
    nonce: &[u8; 13],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; 16],
) {
    unsafe {
        ocrypto_aes_ccm_encrypt(
            ct.as_mut_ptr(),
            tag.as_mut_ptr(),
            16,
            pt.as_ptr(),
            pt.len(),
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            13,
            core::ptr::null(),
            0,
        );
    }
}

/// Software AES-CTR encrypt of `pt` into `ct` under `key` with a 16-byte `iv`.
pub fn aes_ctr_encrypt(key: &[u8], iv: &[u8; 16], pt: &[u8], ct: &mut [u8]) {
    unsafe {
        ocrypto_aes_ctr_encrypt(
            ct.as_mut_ptr(),
            pt.as_ptr(),
            pt.len(),
            key.as_ptr(),
            key.len(),
            iv.as_ptr(),
        );
    }
}

/// Software AES-CBC encrypt of `pt` into `ct` under `key` with a 16-byte `iv`.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], pt: &[u8], ct: &mut [u8]) {
    unsafe {
        ocrypto_aes_cbc_encrypt(
            ct.as_mut_ptr(),
            pt.as_ptr(),
            pt.len(),
            key.as_ptr(),
            key.len(),
            iv.as_ptr(),
        );
    }
}

/// Software SHA-512 of `input`; writes the 64-byte digest.
pub fn sha512(input: &[u8], digest: &mut [u8; 64]) {
    unsafe { ocrypto_sha512(digest.as_mut_ptr(), input.as_ptr(), input.len()) }
}

/// Software SHA-384 of `input`; writes the 48-byte digest.
pub fn sha384(input: &[u8], digest: &mut [u8; 48]) {
    unsafe { ocrypto_sha384(digest.as_mut_ptr(), input.as_ptr(), input.len()) }
}

/// ChaCha20-Poly1305 encrypt of `pt` into `ct` under 32-byte `key` and 12-byte
/// `nonce` (no AAD); writes the 16-byte `tag`.
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; 16],
) {
    unsafe {
        ocrypto_chacha20_poly1305_encrypt(
            tag.as_mut_ptr(),
            ct.as_mut_ptr(),
            pt.as_ptr(),
            pt.len(),
            core::ptr::null(),
            0,
            nonce.as_ptr(),
            12,
            key.as_ptr(),
        );
    }
}

/// P-256 public key `pk` (64 B, big-endian X||Y) from secret key `sk`.
pub fn p256_public_key(sk: &[u8; 32], pk: &mut [u8; 64]) -> bool {
    unsafe { ocrypto_ecdh_p256_public_key(pk.as_mut_ptr(), sk.as_ptr()) == 0 }
}

/// P-256 ECDH shared secret (32-byte X-coord) from `sk` and peer `pub_key`.
pub fn p256_ecdh(
    sk: &[u8; 32],
    pub_key: &[u8; 64],
    out: &mut [u8; 32],
) -> bool {
    unsafe {
        ocrypto_ecdh_p256_common_secret(
            out.as_mut_ptr(),
            sk.as_ptr(),
            pub_key.as_ptr(),
        ) == 0
    }
}

/// P-256 ECDSA sign of `hash` under `sk` with nonce `ek`; writes `sig` (r||s).
pub fn p256_ecdsa_sign_hash(
    hash: &[u8; 32],
    sk: &[u8; 32],
    ek: &[u8; 32],
    sig: &mut [u8; 64],
) -> bool {
    unsafe {
        ocrypto_ecdsa_p256_sign_hash(
            sig.as_mut_ptr(),
            hash.as_ptr(),
            sk.as_ptr(),
            ek.as_ptr(),
        ) == 0
    }
}

/// P-256 ECDSA verify `sig` over `hash` with public key `pub_key`.
pub fn p256_ecdsa_verify_hash(
    hash: &[u8; 32],
    pub_key: &[u8; 64],
    sig: &[u8; 64],
) -> bool {
    unsafe {
        ocrypto_ecdsa_p256_verify_hash(
            sig.as_ptr(),
            hash.as_ptr(),
            pub_key.as_ptr(),
        ) == 0
    }
}

/// Software AES-ECB encrypt of `input` (length a multiple of 16) under `key`
/// (16, 24, or 32 bytes) into `output` (>= `input.len()`).
pub fn aes_ecb_encrypt(key: &[u8], input: &[u8], output: &mut [u8]) {
    unsafe {
        ocrypto_aes_ecb_encrypt(
            output.as_mut_ptr(),
            input.as_ptr(),
            input.len(),
            key.as_ptr(),
            key.len(),
        );
    }
}

/// Software AES-ECB decrypt (counterpart of [`aes_ecb_encrypt`]).
pub fn aes_ecb_decrypt(key: &[u8], input: &[u8], output: &mut [u8]) {
    unsafe {
        ocrypto_aes_ecb_decrypt(
            output.as_mut_ptr(),
            input.as_ptr(),
            input.len(),
            key.as_ptr(),
            key.len(),
        );
    }
}

/// Software AES-GCM encrypt of `input` under `key` with a 12-byte `iv` and no
/// AAD. Writes ciphertext to `output` and a 16-byte tag to `tag`.
pub fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8; 12],
    input: &[u8],
    output: &mut [u8],
    tag: &mut [u8; 16],
) {
    unsafe {
        ocrypto_aes_gcm_encrypt(
            output.as_mut_ptr(),
            tag.as_mut_ptr(),
            16,
            input.as_ptr(),
            input.len(),
            key.as_ptr(),
            key.len(),
            iv.as_ptr(),
            core::ptr::null(),
            0,
        );
    }
}

/// Software AES-CMAC of `msg` under `key`; writes a 16-byte tag.
pub fn aes_cmac(key: &[u8], msg: &[u8], tag: &mut [u8; 16]) {
    unsafe {
        ocrypto_aes_cmac_authenticate(
            tag.as_mut_ptr(),
            16,
            msg.as_ptr(),
            msg.len(),
            key.as_ptr(),
            key.len(),
        );
    }
}

/// Software SHA-256 of `input`; writes the 32-byte digest.
pub fn sha256(input: &[u8], digest: &mut [u8; 32]) {
    unsafe { ocrypto_sha256(digest.as_mut_ptr(), input.as_ptr(), input.len()) }
}

/// Software HMAC-SHA256 of `input` under `key`; writes the 32-byte MAC.
pub fn hmac_sha256(key: &[u8], input: &[u8], mac: &mut [u8; 32]) {
    unsafe {
        ocrypto_hmac_sha256(
            mac.as_mut_ptr(),
            key.as_ptr(),
            key.len(),
            input.as_ptr(),
            input.len(),
        );
    }
}

/// Ed25519 public key from a 32-byte secret key.
pub fn ed25519_public_key(sk: &[u8; 32], pk: &mut [u8; 32]) {
    unsafe { ocrypto_ed25519_public_key(pk.as_mut_ptr(), sk.as_ptr()) }
}

/// Ed25519 sign `m` with secret key `sk` and public key `pk`; writes 64-byte sig.
pub fn ed25519_sign(
    sk: &[u8; 32],
    pk: &[u8; 32],
    m: &[u8],
    sig: &mut [u8; 64],
) {
    unsafe {
        ocrypto_ed25519_sign(
            sig.as_mut_ptr(),
            m.as_ptr(),
            m.len(),
            sk.as_ptr(),
            pk.as_ptr(),
        );
    }
}

/// Ed25519 verify `sig` over `m` with public key `pk`. Returns true if valid.
pub fn ed25519_verify(pk: &[u8; 32], m: &[u8], sig: &[u8; 64]) -> bool {
    unsafe { ocrypto_ed25519_verify(sig.as_ptr(), m.as_ptr(), m.len(), pk.as_ptr()) == 0 }
}

/// X25519 public key `pub = sk·G`.
pub fn x25519_base(sk: &[u8; 32], public: &mut [u8; 32]) {
    unsafe { ocrypto_curve25519_scalarmult_base(public.as_mut_ptr(), sk.as_ptr()) }
}

/// X25519 shared secret `out = sk·peer_pub`.
pub fn x25519_ecdh(sk: &[u8; 32], peer_pub: &[u8; 32], out: &mut [u8; 32]) {
    unsafe {
        ocrypto_curve25519_scalarmult(
            out.as_mut_ptr(),
            sk.as_ptr(),
            peer_pub.as_ptr(),
        );
    }
}
