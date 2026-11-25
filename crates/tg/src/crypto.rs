//! AES-256-CTR, SHA-256 и случайные байты через системную криптографию Windows (CNG, bcrypt.dll).
//! Своей реализации шифров нет: только сборка CTR-режима из блоков AES-ECB.

use std::ffi::c_void;

type Handle = *mut c_void;

// Псевдо-дескрипторы алгоритмов CNG (bcrypt.h, Windows 10+): не нужно открывать провайдер.
const BCRYPT_SHA256_ALG_HANDLE: Handle = 0x0000_0041 as Handle;
const BCRYPT_AES_ECB_ALG_HANDLE: Handle = 0x0000_01b1 as Handle;
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

#[link(name = "bcrypt", kind = "raw-dylib")]
unsafe extern "system" {
    fn BCryptGenerateSymmetricKey(
        alg: Handle,
        key: *mut Handle,
        object: *mut u8,
        object_len: u32,
        secret: *const u8,
        secret_len: u32,
        flags: u32,
    ) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn BCryptEncrypt(
        key: Handle,
        input: *const u8,
        input_len: u32,
        padding: *const c_void,
        iv: *mut u8,
        iv_len: u32,
        output: *mut u8,
        output_len: u32,
        result: *mut u32,
        flags: u32,
    ) -> i32;
    fn BCryptDestroyKey(key: Handle) -> i32;
    fn BCryptGenRandom(alg: Handle, buf: *mut u8, len: u32, flags: u32) -> i32;
    fn BCryptHash(alg: Handle, secret: *const u8, secret_len: u32, input: *const u8, input_len: u32, out: *mut u8, out_len: u32) -> i32;
}

pub fn random(buf: &mut [u8]) {
    // SAFETY: буфер наш, длина передана.
    let status = unsafe { BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    assert_eq!(status, 0, "BCryptGenRandom: 0x{status:08x}");
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let input = parts.concat();
    let mut out = [0u8; 32];
    // SAFETY: вход и выход — наши буферы с переданными длинами.
    let status = unsafe {
        BCryptHash(BCRYPT_SHA256_ALG_HANDLE, std::ptr::null(), 0, input.as_ptr(), input.len() as u32, out.as_mut_ptr(), 32)
    };
    assert_eq!(status, 0, "BCryptHash: 0x{status:08x}");
    out
}

/// AES-256-CTR со 128-битным счётчиком big-endian — так шифруется obfuscated2. Состояние сохраняется между вызовами.
pub struct AesCtr {
    key: Handle,
    counter: [u8; 16],
    keystream: [u8; 16],
    /// Сколько байт текущего блока ключевого потока уже использовано (16 — нужен новый блок).
    used: usize,
}

// SAFETY: ключ CNG — неизменяемый объект; один AesCtr используется одним потоком за раз.
unsafe impl Send for AesCtr {}

impl AesCtr {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        let mut handle: Handle = std::ptr::null_mut();
        // SAFETY: объект ключа выделяет CNG (null, 0); ключ копируется внутрь.
        let status = unsafe {
            BCryptGenerateSymmetricKey(BCRYPT_AES_ECB_ALG_HANDLE, &mut handle, std::ptr::null_mut(), 0, key.as_ptr(), 32, 0)
        };
        assert_eq!(status, 0, "BCryptGenerateSymmetricKey: 0x{status:08x}");
        Self { key: handle, counter: *iv, keystream: [0; 16], used: 16 }
    }

    /// Шифрует блоки на месте (длина кратна 16).
    fn ecb(&self, blocks: &mut [u8]) {
        let mut written = 0u32;
        let len = blocks.len() as u32;
        // SAFETY: CNG допускает шифрование на месте; буфер наш, длина кратна блоку, без дополнения.
        let status = unsafe {
            BCryptEncrypt(self.key, blocks.as_ptr(), len, std::ptr::null(), std::ptr::null_mut(), 0, blocks.as_mut_ptr(), len, &mut written, 0)
        };
        assert_eq!(status, 0, "BCryptEncrypt: 0x{status:08x}");
    }

    fn next_counter(&mut self) -> [u8; 16] {
        let current = self.counter;
        for b in self.counter.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        current
    }

    /// XOR данных с ключевым потоком. Целые блоки — одним вызовом CNG.
    pub fn apply(&mut self, mut data: &mut [u8]) {
        while self.used < 16 && !data.is_empty() {
            data[0] ^= self.keystream[self.used];
            self.used += 1;
            data = &mut data[1..];
        }
        if data.is_empty() {
            return;
        }
        let blocks = data.len().div_ceil(16);
        let mut stream = Vec::with_capacity(blocks * 16);
        for _ in 0..blocks {
            stream.extend_from_slice(&self.next_counter());
        }
        self.ecb(&mut stream);
        for (d, k) in data.iter_mut().zip(&stream) {
            *d ^= k;
        }
        let tail = data.len() % 16;
        if tail != 0 {
            self.keystream.copy_from_slice(&stream[stream.len() - 16..]);
            self.used = tail;
        }
    }

    pub fn skip(&mut self, count: usize) {
        self.apply(&mut vec![0; count]);
    }
}

impl Drop for AesCtr {
    fn drop(&mut self) {
        // SAFETY: ключ создан в new и уничтожается один раз.
        unsafe { BCryptDestroyKey(self.key) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(sha256(&[b"abc"]).to_vec(), hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        assert_eq!(sha256(&[b"a", b"bc"]), sha256(&[b"abc"]));
    }

    #[test]
    fn aes256_ctr_matches_nist_sp800_38a() {
        // NIST SP 800-38A, F.5.5 CTR-AES256.Encrypt.
        let key: [u8; 32] = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").try_into().unwrap();
        let iv: [u8; 16] = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").try_into().unwrap();
        let plain = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        let expected = hex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");

        let mut whole = plain.clone();
        AesCtr::new(&key, &iv).apply(&mut whole);
        assert_eq!(whole, expected);

        // По кускам разной длины — тот же поток (состояние между вызовами).
        let mut ctr = AesCtr::new(&key, &iv);
        let mut pieces = plain.clone();
        let (a, rest) = pieces.split_at_mut(5);
        let (b, c) = rest.split_at_mut(27);
        ctr.apply(a);
        ctr.apply(b);
        ctr.apply(c);
        assert_eq!(pieces, expected);

        let mut skipped = AesCtr::new(&key, &iv);
        skipped.skip(16);
        let mut second = plain[16..32].to_vec();
        skipped.apply(&mut second);
        assert_eq!(second, expected[16..32]);
    }

    #[test]
    fn counter_carries_over_bytes() {
        let mut ctr = AesCtr::new(&[0; 32], &[0xff; 16]);
        assert_eq!(ctr.next_counter(), [0xff; 16]);
        assert_eq!(ctr.next_counter(), [0; 16]);
    }

    #[test]
    fn random_is_not_constant() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        random(&mut a);
        random(&mut b);
        assert_ne!(a, b);
    }
}
