use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

use hex::{decode, encode};
use ring::{
    aead::{self, Aad, BoundKey, Nonce, NonceSequence, AES_256_GCM, NONCE_LEN},
    rand::{SecureRandom, SystemRandom},
};

struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);

        self.0 += 1;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

pub struct Crypter {
    key: String,
}

impl Crypter {
    pub fn new(key: String) -> Self {
        Self { key }
    }

    pub fn crypt(&mut self, file_path: String) -> String {
        if !self.key.is_empty() {
            self.decrypt(file_path);
            String::new()
        } else {
            self.encrypt(file_path)
        }
    }

    fn encrypt(&mut self, file_path: String) -> String {
        let mut key_bytes = if self.key.is_empty() {
            vec![0; AES_256_GCM.key_len()]
        } else {
            decode(&self.key).unwrap()
        };

        let random = SystemRandom::new();

        if self.key.is_empty() {
            random.fill(&mut key_bytes).unwrap();
        }

        let unbound_key = aead::UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();

        let nonce_key = CounterNonceSequence(1);
        let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_key);

        let mut file = File::open(&file_path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut contents)
            .unwrap();

        let mut file_name = PathBuf::from(&file_path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .as_bytes()
            .to_owned();
        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut file_name)
            .unwrap();
        let mut output_file = File::create(encode(file_name)).unwrap();
        output_file.write_all(encode(&contents).as_bytes()).unwrap();

        fs::remove_file(&file_path).unwrap();

        if self.key.is_empty() {
            let key = encode(key_bytes);
            self.key = key.clone();
            key
        } else {
            String::new()
        }
    }

    fn decrypt(&self, file_path: String) {
        let key_bytes = decode(&self.key).unwrap();

        let unbound_key = aead::UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();

        let nonce_key = CounterNonceSequence(1);
        let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_key);

        let mut file = File::open(&file_path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        contents = decode(contents).unwrap();

        let contents = opening_key
            .open_in_place(Aad::empty(), &mut contents)
            .unwrap();

        let mut file_name = PathBuf::from(&file_path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .as_bytes()
            .to_owned();
        file_name = decode(file_name).unwrap();
        let file_name = opening_key
            .open_in_place(Aad::empty(), &mut file_name)
            .unwrap();
        let mut output_file =
            fs::File::create(String::from_utf8(file_name.to_owned()).unwrap()).unwrap();
        let _ = output_file.write_all(contents);

        fs::remove_file(&file_path).unwrap();
    }
}
