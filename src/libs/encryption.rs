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
    let end = if a.len() < 32 { a.len() } else { 32 };
    let h = &a[..end];
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




fn pad(data: &[u8], block_size: usize) -> Result<String> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + pad_len);
    padded.extend_from_slice(data);
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    Ok(String::from_utf8(padded)?)
}


fn aes_encrypt(password: &str, key: Vec<u8>,iv: Vec<u8>) -> Result<Vec<u8>> {

    let mut buf = [0u8; 1024]; // Assuming maximum plaintext length of 1024 bytes

    let padded_msg = pad(password.as_bytes(),16)?;
    let pt_len = padded_msg.len();
    buf[..pt_len].copy_from_slice(padded_msg.as_bytes());

    let cipher = Aes256CbcEnc::new(key.as_slice().into(), iv.as_slice().into());
    let ciphertext_res = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf,pt_len);
    let ciphertext = match ciphertext_res {
        Ok(ct) => ct,
        Err(err) => {
            let error_msg = format!("Encryption failed: {}", err);
            return Err(Error::msg(error_msg).context("Encryption failed"));
        }
    };

    Ok(ciphertext.to_vec())
}

pub fn encrypt(username: &str, password: &str, salt: Option<Vec<u8>>) -> Result<String> {
    let secret = key_fnv32(username)?;
    let keylen = 32;
    let ivlen = 16;
    let DerivedMd5 { key, iv, salt } = derive_key_and_iv(&secret,salt,keylen,ivlen);

    let ciphertext = aes_encrypt(password, key, iv)?;


    let mut result = b"Salted__".to_vec();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&ciphertext);

    Ok(BASE64_STANDARD.encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn pad_test() {
        let test_cases = [
            ("","\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}\u{10}"),
            ("test","test\u{0c}\u{0c}\u{0c}\u{0c}\u{0c}\u{0c}\u{0c}\u{0c}\u{0c}\u{0c}\u{0c}\u{0c}"),
            ("trial","trial\u{0b}\u{0b}\u{0b}\u{0b}\u{0b}\u{0b}\u{0b}\u{0b}\u{0b}\u{0b}\u{0b}"),
            ("abcdefghijklmaopqrstuvwxyz","abcdefghijklmaopqrstuvwxyz\u{06}\u{06}\u{06}\u{06}\u{06}\u{06}")
        ];
        for case in test_cases {
            assert_eq!(pad(case.0.as_bytes(),16).unwrap(),case.1);
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
            ("","","71e000957d24d0bc3830940866801c8435d58bad2d01772340f02698fdd3a761d9afa4611277e34d36d4faaeeb79cff2f130db33f22e426e7cd0723d888a776b"),
            ("","testinput","eda590006ee59ccdf3aef98acf92146860a77392d8953cb64e1cbadd1b6922156e295611c54e5b1d63cc4ec722c692a998d298f29b62af6b09ebab0416d9d762"),
            ("anotherone","","f2bf6335e54cf84b95cc33ca688201a38fd2f96e5e1f70791fe5e675ea69088720d22541acd136515879ee7468e8e2e9a634fd8f9b2eb759738818a772de9780"),
            ("sjsjsjjwjwjwjwjwjjwjwjsjsjajajaja","LAMSnsnshafSLSKSksshanzzz","d779d713a69d5f66cb393363669a4d72c1590b6e2e453eeb9d643ee5d880574bbf052f2f664aa2b00a86d82ee82337937eb6b5f149f1e68a6a8e85cbc6aa38da")
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

    #[test]
    fn encrypt_test() {
        let test_cases = [
            ("usernameusernameusernameusernameusernameusername","passwordusernameusernameusernameusernameusername","U2FsdGVkX19gXVQd8kXBiiG00MCQLLRThvTK9BxcK5OIuEFvBcwkI7m4itEfNhI16M2BBnv+0r8sn4AhOuFBVnQ5BoZPzCcXLuteysreSr8="),
             ("username","password","U2FsdGVkX18WZSCkkgVIZpFJ5m3ExAPUmI33C4+JMq0="),
             ("testusername","testpassword","U2FsdGVkX19Jw2bOvcimEspUaNQMdtCvHX0KkWH1158="),
             ("","password","U2FsdGVkX1/AIHLaimqTbDA90yZtN47/n9B3DMvDUOk="),
             ("username","","U2FsdGVkX1/Mhy95lysn8VqyxOp4u6Zdlp8mXqSYLDI="),
            ("","","U2FsdGVkX1/y2D4EkZJFc2VRdp63C3b0EFk7mic1qpI=")
             ];

        let salt: Vec<u8> = vec![0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08];
        for case in test_cases {
            assert_eq!(encrypt(case.0,case.1,Some(salt.clone())).unwrap(),case.2);
        }
    }

    #[test]
    fn aes_encrypt_test() {
        let key = "abcdefghijklmaopqrstuvwxyzaaaaaa".as_bytes().to_vec(); // must be 32 chars
        assert!(key.len() == 32);
        let iv: Vec<u8> = [0x01].to_vec();
        let test_cases = [
                ("",""),
                ("123",""),
                ("1jajajssjsammaja",""),
                ("abcdefghijklmaopqrstuvwxyz","")
             ];

        for case in test_cases {
            assert_eq!(String::from_utf8(aes_encrypt(case.0,key.clone(),iv.clone()).unwrap()).unwrap(),case.1);
        }
    }


}
