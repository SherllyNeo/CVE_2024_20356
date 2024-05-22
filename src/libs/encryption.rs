use anyhow::{Error,Result,Context};
use aes::Aes256;
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::Rng;
use sha2::{Sha512, Digest};
use base64::prelude::*;
use hex;
use std::str;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type HmacSha512 = Hmac<Sha512>;

fn key_fnv32(a: &str) -> Result<String> {
    let h: &str;
    if a.len() < 32 {
        h = &a;
    }
    else {
	    h = &a[0..32];
    }
	let mut e = 40389;
	let f = h.len() / 4;
	for i in 0..f {
        e ^= h.chars().nth(i).context("Failed to get character")? as u32;
        e = e.wrapping_add(e << 1);
    }
    Ok(e.to_string())
}

pub fn hash_fnv32(a: &str, b: &str) -> Result<String> {
    let mut e = 40389;
    let h = &a[..32];
    let f = h.len() / 4;

    for i in 0..f {
        let byte = a.as_bytes()[i];
        e ^= byte as u32;
        e = e.wrapping_add(e << 1);
    }

    let mut mac = HmacSha512::new_from_slice(&(e.to_string().into_bytes())).context("HMAC can take key of any size")?;

    mac.update(b.as_bytes());

    let result = mac.finalize().into_bytes();
    Ok(hex::encode(result.as_slice()))
}

#[derive(Debug)]
struct DerivedMd5 {
    key: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>
}


fn derive_key_and_iv(secret: &str,salt: Option<Vec<u8>>,keylen: usize, ivlen: usize) -> DerivedMd5 {
    let mut rng = rand::thread_rng();
    let salt = salt.unwrap_or((0..8).map(|_| rng.gen()).collect());


    let mut secret_bytes = secret.as_bytes().to_vec();
    secret_bytes.extend_from_slice(&salt);

    let mut hasher = Md5::new();
    hasher.update(&secret_bytes);
    let mut k = hasher.finalize_reset().to_vec();
    let mut w = k.clone();

    while w.len() < (keylen + ivlen) {
        hasher.update(&k);
        hasher.update(&secret_bytes);
        k = hasher.finalize_reset().to_vec();
        w.extend_from_slice(&k);
    }

    let key = w[..keylen].to_vec();
    let iv = w[keylen..(keylen + ivlen)].to_vec();

    DerivedMd5 {
        key,
        iv,
        salt
    }

}




fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}



pub fn encrypt(username: &str, password: &str,salt: Option<Vec<u8>>) -> Result<String> {
    let secret = key_fnv32(username)?;
    let keylen = 32;
    let ivlen = 16;
    let DerivedMd5 { key, iv, salt } = derive_key_and_iv(&secret,salt,keylen,ivlen);

    let mut buf = [0u8; 1024]; // Assuming maximum plaintext length of 1024 bytes

    let padded_msg = pad(password.as_bytes(),password.as_bytes().len());
    let pt_len = padded_msg.len();
    buf[..pt_len].copy_from_slice(padded_msg.as_slice());

    let cipher = Aes256CbcEnc::new(key.as_slice().into(), iv.as_slice().into());
    let ciphertext = match cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len) {
        Ok(ct) => ct,
        Err(err) => {
            let error_msg = format!("Encryption failed: {}", err);
            return Err(Error::msg(error_msg).context("Encryption failed"));
        }
    };

    let mut result = b"Salted__".to_vec();
    result.extend_from_slice(&salt);
    result.extend_from_slice(ciphertext);

    Ok(BASE64_STANDARD.encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_test() {
        let test_cases = [
            ("usernameusernameusernameusernameusernameusername","passwordusernameusernameusernameusernameusername","U2FsdGVkX19gXVQd8kXBiiG00MCQLLRThvTK9BxcK5OIuEFvBcwkI7m4itEfNhI16M2BBnv+0r8sn4AhOuFBVnQ5BoZPzCcXLuteysreSr8="),
             ("username","password","U2FsdGVkX18WZSCkkgVIZpFJ5m3ExAPUmI33C4+JMq0="),
             ("testusername","testpassword","U2FsdGVkX19Jw2bOvcimEspUaNQMdtCvHX0KkWH1158="),
             ("","password","U2FsdGVkX1/AIHLaimqTbDA90yZtN47/n9B3DMvDUOk="),
             ("username","","U2FsdGVkX1/Mhy95lysn8VqyxOp4u6Zdlp8mXqSYLDI="),
           // TODO ("","",todo)
             ];

        let salt: Vec<u8> = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08];
        for case in test_cases {
            assert_eq!(encrypt(case.0,case.1,Some(salt.clone())).unwrap(),case.2);
        }
    }

    #[test]
    fn key_fnv32_test() {
        let test_cases = [
            ("","40389"),
            ("testinput","363618"),
            ("anotherone","362886"),
        ];
        for case in test_cases {
            assert_eq!(key_fnv32(case.0).unwrap(),case.1);
        }
    }
    
    #[test]
    fn hash_fnv32_test() {
        let test_cases = [
            ("","testinput","todo"),
            ("testinput","input","todo"),
            ("anotherone","","todo"),
            ("","","todo")
        ];
        for case in test_cases {
            assert_eq!(hash_fnv32(case.0,case.1).unwrap(),case.2);
        }
    }

    #[test]
    fn derive_key_and_iv_test() {
        let salt: Vec<u8> = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08];
        let test_cases = ["","testsecret","finalsecret"];
        for case in test_cases {
            let md5 = derive_key_and_iv(case,Some(salt.clone()),32,16);
            println!("case: {case} {:?}",md5);
        }
    }


}
