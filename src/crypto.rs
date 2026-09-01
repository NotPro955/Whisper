#![allow(dead_code)]
use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use p256::{
    ecdh::EphemeralSecret,
    PublicKey,
    EncodedPoint,
    elliptic_curve::sec1::FromEncodedPoint,
};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use anyhow::{Result, bail};

pub const ACCOUNT_KEY_SIZE: usize = 16;
pub const AES_BLOCK_SIZE: usize = 16;

pub fn aes_128_encrypt(key: &[u8; 16], plaintext: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(plaintext);
    cipher.encrypt_block(&mut block);
    block.into()
}

pub fn aes_128_decrypt(key: &[u8; 16], ciphertext: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(ciphertext);
    cipher.decrypt_block(&mut block);
    block.into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub struct ECDHKeyPair {
    pub secret: EphemeralSecret,
    pub public_key_bytes: [u8; 64],
}

pub fn generate_secp256r1_keypair() -> ECDHKeyPair {
    let secret = EphemeralSecret::random(&mut OsRng);
    let public_key = secret.public_key();
    let encoded = EncodedPoint::from(public_key);
    let x = encoded.x().expect("x coordinate").as_slice();
    let y = encoded.y().expect("y coordinate").as_slice();
    let mut public_key_bytes = [0u8; 64];
    public_key_bytes[..32].copy_from_slice(x);
    public_key_bytes[32..].copy_from_slice(y);
    ECDHKeyPair { secret, public_key_bytes }
}

pub fn derive_shared_secret_from_provider_public_key(
    keypair: ECDHKeyPair,
    provider_public_key_bytes: &[u8],
) -> Result<[u8; 16]> {
    if provider_public_key_bytes.len() != 64 {
        bail!("Provider public key must be 64 bytes");
    }
    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(provider_public_key_bytes);
    let encoded = EncodedPoint::from_bytes(&uncompressed)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
    let provider_pk_opt = PublicKey::from_encoded_point(&encoded);
    let provider_pk = if provider_pk_opt.is_some().into() {
        provider_pk_opt.unwrap()
    } else {
        bail!("Failed to parse provider public key");
    };
    let shared = keypair.secret.diffie_hellman(&provider_pk);
    let hash = sha256(shared.raw_secret_bytes());
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash[..16]);
    Ok(key)
}

pub fn derive_aes_key_from_account_key(account_key: &[u8]) -> Result<[u8; 16]> {
    if account_key.len() != ACCOUNT_KEY_SIZE {
        bail!("Account key must be {} bytes", ACCOUNT_KEY_SIZE);
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(account_key);
    Ok(key)
}

pub fn generate_random_salt(length: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; length];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn generate_account_key() -> [u8; ACCOUNT_KEY_SIZE] {
    use rand::RngCore;
    let mut key = [0u8; ACCOUNT_KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn encrypt_account_key_for_write(account_key: &[u8; 16], shared_secret: &[u8; 16]) -> [u8; 16] {
    aes_128_encrypt(shared_secret, account_key)
}
