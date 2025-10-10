use aes::Aes128;
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use rand::{rngs::OsRng, RngCore};
use std::time::Instant;

const BLOCK_SIZE: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("insecure input block")]
    InsecureInput,
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("ciphertext too short")]
    SourceTooShort,
    #[error("packet ordering violation")]
    PacketOrdering,
    #[error("duplicate packet")]
    DuplicatePacket,
    #[error("authentication tag mismatch")]
    TagMismatch,
    #[error("potentially tampered block")]
    TamperedBlock,
}

#[derive(Clone)]
pub struct CryptStateOcb2 {
    aes: Aes128,
    raw_key: [u8; BLOCK_SIZE],
    encrypt_iv: [u8; BLOCK_SIZE],
    decrypt_iv: [u8; BLOCK_SIZE],
    decrypt_history: [u8; 0x100],
    pub ui_good: u32,
    pub ui_late: u32,
    pub ui_lost: i32,
    pub t_last_good: Option<Instant>,
}

impl CryptStateOcb2 {
    pub fn new() -> Self {
        let mut key = [0u8; BLOCK_SIZE];
        let mut enc_iv = [0u8; BLOCK_SIZE];
        let mut dec_iv = [0u8; BLOCK_SIZE];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut enc_iv);
        OsRng.fill_bytes(&mut dec_iv);
        let aes = Aes128::new(GenericArray::from_slice(&key));
        Self {
            aes,
            raw_key: key,
            encrypt_iv: enc_iv,
            decrypt_iv: dec_iv,
            decrypt_history: [0u8; 0x100],
            ui_good: 0,
            ui_late: 0,
            ui_lost: 0,
            t_last_good: None,
        }
    }

    pub fn gen_key(&mut self) {
        OsRng.fill_bytes(&mut self.raw_key);
        OsRng.fill_bytes(&mut self.encrypt_iv);
        OsRng.fill_bytes(&mut self.decrypt_iv);
        self.aes = Aes128::new(GenericArray::from_slice(&self.raw_key));
        self.decrypt_history = [0; 0x100];
    }

    pub fn set_key(&mut self, key: &[u8], encrypt_iv: &[u8], decrypt_iv: &[u8]) {
        assert_eq!(key.len(), BLOCK_SIZE);
        assert_eq!(encrypt_iv.len(), BLOCK_SIZE);
        assert_eq!(decrypt_iv.len(), BLOCK_SIZE);
        self.raw_key.copy_from_slice(key);
        self.encrypt_iv.copy_from_slice(encrypt_iv);
        self.decrypt_iv.copy_from_slice(decrypt_iv);
        self.aes = Aes128::new(GenericArray::from_slice(&self.raw_key));
        self.decrypt_history = [0; 0x100];
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let mut iv = self.encrypt_iv;
        increment_iv(&mut iv, 0);
        self.encrypt_iv = iv;
        let (cipher, tag) = ocb_encrypt(&self.aes, plaintext, &iv, false)?;
        let mut out = Vec::with_capacity(4 + cipher.len());
        out.push(iv[0]);
        out.extend_from_slice(&tag[..3]);
        out.extend_from_slice(&cipher);
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        if ciphertext.len() < 4 {
            return Err(DecryptError::SourceTooShort);
        }

        let mut div = self.decrypt_iv;
        let ivbyte = ciphertext[0];
        let mut late = false;
        let mut lost = 0i32;

        if div[0].wrapping_add(1) == ivbyte {
            if ivbyte > div[0] {
                div[0] = ivbyte;
            } else if ivbyte < div[0] {
                div[0] = ivbyte;
                increment_iv(&mut div, 1);
            } else {
                return Err(DecryptError::PacketOrdering);
            }
        } else {
            let mut diff = ivbyte as i32 - div[0] as i32;
            if diff > 128 {
                diff -= 256;
            } else if diff < -128 {
                diff += 256;
            }

            if ivbyte < div[0] && (-30..0).contains(&diff) {
                late = true;
                lost = -1;
                div[0] = ivbyte;
            } else if ivbyte > div[0] && (-30..0).contains(&diff) {
                late = true;
                lost = -1;
                div[0] = ivbyte;
                decrement_iv(&mut div, 1);
            } else if ivbyte > div[0] && diff > 0 {
                lost = (ivbyte - div[0] - 1) as i32;
                div[0] = ivbyte;
            } else if ivbyte < div[0] && diff > 0 {
                lost = (0x100 - div[0] as i32 + ivbyte as i32 - 1) as i32;
                div[0] = ivbyte;
                increment_iv(&mut div, 1);
            } else {
                return Err(DecryptError::PacketOrdering);
            }

            if self.decrypt_history[div[0] as usize] == div[1] {
                return Err(DecryptError::DuplicatePacket);
            }
        }

        let encrypted = &ciphertext[4..];
        let len_plain = encrypted.len();
        let (plain, tag) = ocb_decrypt(&self.aes, encrypted, &div, len_plain, false)?;

        if tag[..3] != ciphertext[1..4] {
            return Err(DecryptError::TagMismatch);
        }

        self.decrypt_history[div[0] as usize] = div[1];
        if !late {
            self.decrypt_iv = div;
        } else {
            self.ui_late += 1;
        }

        self.ui_good += 1;
        self.ui_lost += lost;
        self.t_last_good = Some(Instant::now());

        Ok(plain)
    }

    pub fn raw_key(&self) -> [u8; BLOCK_SIZE] {
        self.raw_key
    }

    pub fn encrypt_iv(&self) -> [u8; BLOCK_SIZE] {
        self.encrypt_iv
    }

    pub fn decrypt_iv(&self) -> [u8; BLOCK_SIZE] {
        self.decrypt_iv
    }

    pub fn set_encrypt_iv(&mut self, iv: &[u8]) {
        assert_eq!(iv.len(), BLOCK_SIZE);
        self.encrypt_iv.copy_from_slice(iv);
    }

    pub fn set_decrypt_iv(&mut self, iv: &[u8]) {
        assert_eq!(iv.len(), BLOCK_SIZE);
        self.decrypt_iv.copy_from_slice(iv);
        self.decrypt_history = [0; 0x100];
    }
}

fn ocb_encrypt(
    aes: &Aes128,
    plain: &[u8],
    nonce: &[u8; BLOCK_SIZE],
    insecure: bool,
) -> Result<(Vec<u8>, [u8; BLOCK_SIZE]), EncryptError> {
    let mut delta = encrypt_block(aes, nonce);
    let mut checksum = [0u8; BLOCK_SIZE];
    let mut encrypted = vec![0u8; plain.len()];
    let mut pos = 0;
    let mut last_full_block: Option<[u8; BLOCK_SIZE]> = None;

    while plain.len() - pos > BLOCK_SIZE {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(&plain[pos..pos + BLOCK_SIZE]);
        delta = s2(&delta);
        let tmp = xor_block(&delta, &block);
        let enc = xor_block(&delta, &encrypt_block(aes, &tmp));
        checksum = xor_block(&checksum, &block);
        encrypted[pos..pos + BLOCK_SIZE].copy_from_slice(&enc);
        pos += BLOCK_SIZE;
        last_full_block = Some(block);
    }

    if !insecure {
        if let Some(block) = last_full_block {
            if block[..BLOCK_SIZE - 1].iter().all(|&b| b == 0) {
                return Err(EncryptError::InsecureInput);
            }
        }
    }

    let len_remaining = plain.len() - pos;
    delta = s2(&delta);
    let pad_in = length_block(len_remaining);
    let pad = encrypt_block(aes, &xor_block(&pad_in, &delta));

    let mut plain_block = [0u8; BLOCK_SIZE];
    plain_block[..len_remaining].copy_from_slice(&plain[pos..]);
    plain_block[len_remaining..].copy_from_slice(&pad[len_remaining..]);

    checksum = xor_block(&checksum, &plain_block);
    let encrypted_block = xor_block(&pad, &plain_block);
    encrypted[pos..].copy_from_slice(&encrypted_block[..len_remaining]);

    let doubled = s2(&delta);
    let delta_tag = xor_block(&xor_block(&delta, &doubled), &checksum);
    let tag = encrypt_block(aes, &delta_tag);

    Ok((encrypted, tag))
}

fn ocb_decrypt(
    aes: &Aes128,
    encrypted: &[u8],
    nonce: &[u8; BLOCK_SIZE],
    len_plain: usize,
    insecure: bool,
) -> Result<(Vec<u8>, [u8; BLOCK_SIZE]), DecryptError> {
    let mut delta = encrypt_block(aes, nonce);
    let mut checksum = [0u8; BLOCK_SIZE];
    let mut plain = vec![0u8; len_plain];
    let mut pos = 0;

    while len_plain - pos > BLOCK_SIZE {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(&encrypted[pos..pos + BLOCK_SIZE]);
        delta = s2(&delta);
        let tmp = decrypt_block(aes, &xor_block(&delta, &block));
        let plain_block = xor_block(&delta, &tmp);
        checksum = xor_block(&checksum, &plain_block);
        plain[pos..pos + BLOCK_SIZE].copy_from_slice(&plain_block);
        pos += BLOCK_SIZE;
    }

    let len_remaining = len_plain - pos;
    delta = s2(&delta);
    let pad_in = length_block(len_remaining);
    let pad = encrypt_block(aes, &xor_block(&pad_in, &delta));
    let mut encrypted_block = [0u8; BLOCK_SIZE];
    encrypted_block[..len_remaining].copy_from_slice(&encrypted[pos..]);
    let plain_block = xor_block(&encrypted_block, &pad);
    checksum = xor_block(&checksum, &plain_block);
    plain[pos..].copy_from_slice(&plain_block[..len_remaining]);

    if !insecure && plain_block[..BLOCK_SIZE - 1] == delta[..BLOCK_SIZE - 1] {
        return Err(DecryptError::TamperedBlock);
    }

    let delta_tag = xor_block(&xor_block(&delta, &s2(&delta)), &checksum);
    let tag = encrypt_block(aes, &delta_tag);

    Ok((plain, tag))
}

fn encrypt_block(aes: &Aes128, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut ba = (*block).into();
    aes.encrypt_block(&mut ba);
    ba.into()
}

fn decrypt_block(aes: &Aes128, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut ba = (*block).into();
    aes.decrypt_block(&mut ba);
    ba.into()
}

fn increment_iv(iv: &mut [u8; BLOCK_SIZE], start: usize) {
    for i in start..BLOCK_SIZE {
        iv[i] = iv[i].wrapping_add(1);
        if iv[i] != 0 {
            break;
        }
    }
}

fn decrement_iv(iv: &mut [u8; BLOCK_SIZE], start: usize) {
    for i in start..BLOCK_SIZE {
        iv[i] = iv[i].wrapping_sub(1);
        if iv[i] != u8::MAX {
            break;
        }
    }
}

fn xor_block(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut out = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn length_block(len: usize) -> [u8; BLOCK_SIZE] {
    let mut out = [0u8; BLOCK_SIZE];
    let len_bits = (len as u64) * 8;
    out[8..].copy_from_slice(&len_bits.to_be_bytes());
    out
}

fn s2(block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut low = u64::from_be_bytes(block[..8].try_into().unwrap());
    let mut high = u64::from_be_bytes(block[8..].try_into().unwrap());
    let carry = (low >> 63) & 1;
    low = ((low << 1) | (high >> 63)) & u64::MAX;
    high = ((high << 1) ^ ((carry as u64) * 0x87)) & u64::MAX;
    let mut out = [0u8; BLOCK_SIZE];
    out[..8].copy_from_slice(&low.to_be_bytes());
    out[8..].copy_from_slice(&high.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ocb_encrypt_matches_vectors() {
        let key = [0x00u8; 16];
        let nonce = [0x00u8; 16];
        let mut cipher = CryptStateOcb2::new();
        cipher.set_key(&key, &nonce, &nonce);

        let plain = (0u8..40).collect::<Vec<_>>();
        let (encrypted, tag) = ocb_encrypt(&cipher.aes, &plain, &nonce, false).unwrap();
        let expected_cipher: [u8; 40] = [
            0x47, 0x85, 0x1e, 0xc6, 0xa6, 0x48, 0xee, 0xdc, 0xe6, 0x1f, 0x89, 0x1e, 0xd5, 0xcd,
            0xad, 0x49, 0x66, 0x93, 0xf1, 0x73, 0x4a, 0x75, 0x6e, 0xe1, 0x7b, 0xb6, 0xcf, 0x22,
            0xbe, 0x79, 0xd5, 0xf8, 0x16, 0x1a, 0x0a, 0xed, 0x8c, 0x2e, 0x0a, 0x5e,
        ];
        assert_eq!(encrypted, expected_cipher);
        let expected_tag: [u8; 16] = [
            0x8e, 0x8a, 0x45, 0x80, 0xb9, 0x2d, 0xaa, 0xde, 0x95, 0x38, 0x1d, 0x37, 0xec, 0x46,
            0x37, 0x2d,
        ];
        assert_eq!(tag, expected_tag);
    }

    #[test]
    fn crypt_state_roundtrip() {
        let mut enc = CryptStateOcb2::new();
        let mut dec = CryptStateOcb2::new();
        dec.set_key(&enc.raw_key(), &enc.decrypt_iv(), &enc.encrypt_iv());

        let payload = b"voice payload data";
        let cipher = enc.encrypt(payload).unwrap();
        let plain = dec.decrypt(&cipher).unwrap();

        assert_eq!(plain, payload);
    }
}
