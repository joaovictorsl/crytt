use std::{fs, io::{Read, Write}};

use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use spki::{DecodePublicKey, EncodePublicKey};
use base64::{engine::general_purpose, Engine as _};

pub mod rsa;
pub mod ecdsa;

#[derive(Debug)]
pub enum Error {
    ExportKeyError(String),
    LoadKeyPairError(String),
    GenerateKeyPairError(String),
}

pub trait KeyPair {
    type PrivateKey: DecodePrivateKey + EncodePrivateKey;
    type PublicKey: DecodePublicKey + EncodePublicKey;

    fn new(
        pkey: Self::PublicKey,
        skey: Self::PrivateKey,
    ) -> Self;

    fn pkey(&self) -> &Self::PublicKey;
    fn skey(&self) -> &Self::PrivateKey;
}

pub fn load_keypair<T: KeyPair>(spath: &str, ppath: &str) -> Result<T, Error> {
    let s_encoded_b64 = read_file_as_string(spath)?; // Read as string
    let p_encoded_b64 = read_file_as_string(ppath)?; // Read as string

    // Decode Base64 strings back to DER bytes
    let s_der_bytes = general_purpose::STANDARD.decode(&s_encoded_b64)
        .map_err(|e| Error::LoadKeyPairError(format!("Failed to base64 decode private key: {}", e)))?;
    let p_der_bytes = general_purpose::STANDARD.decode(&p_encoded_b64)
        .map_err(|e| Error::LoadKeyPairError(format!("Failed to base64 decode public key: {}", e)))?;

    let skey = DecodePrivateKey::from_pkcs8_der(&s_der_bytes)
        .map_err(|e| Error::LoadKeyPairError(format!("Failed to decode private key DER: {}", e)))?;
    let pkey = DecodePublicKey::from_public_key_der(&p_der_bytes)
        .map_err(|e| Error::LoadKeyPairError(format!("Failed to decode public key DER: {}", e)))?;

    Ok(KeyPair::new(pkey, skey))
}

// You'll need a new helper function to read file content as a String
fn read_file_as_string(path: &str) -> Result<String, Error> {
    let mut file: fs::File;
    match fs::File::open(path) {
        Ok(f) => file = f,
        Err(err) => return Err(Error::LoadKeyPairError(err.to_string())),
    }

    let mut content = String::new();
    match file.read_to_string(&mut content) { // Use read_to_string for text files
        Ok(_) => Ok(content),
        Err(err) => return Err(Error::LoadKeyPairError(err.to_string())),
    }
}

pub fn export_keypair_to_file<T: KeyPair>(keypair: &T, spath: &str, ppath: &str) -> Result<(), Error> {
    let sexported = encode_skey_to_export(keypair.skey())?;
    let pexported = encode_pkey_to_export(keypair.pkey())?;

    let mut sfile = fs::File::create(spath).unwrap();
    let mut pfile = fs::File::create(ppath).unwrap();

    sfile.write_all(sexported.as_bytes()).unwrap();
    pfile.write_all(pexported.as_bytes()).unwrap();

    Ok(())
}

pub fn encode_skey_to_export<T: EncodePrivateKey>(skey: &T) -> Result<String, Error> {
    let der_bytes = match skey.to_pkcs8_der() {
        Ok(res) => res.to_bytes(),
        Err(e) => return Err(Error::ExportKeyError(e.to_string())),
    };

    let base64_encoded = general_purpose::STANDARD.encode(&der_bytes);
    Ok(base64_encoded)
}

pub fn encode_pkey_to_export<T: EncodePublicKey>(pkey: &T) -> Result<String, Error> {
    let der_bytes = match pkey.to_public_key_der() {
        Ok(res) => res.to_vec(),
        Err(e) => return Err(Error::ExportKeyError(e.to_string())),
    };

    let base64_encoded = general_purpose::STANDARD.encode(&der_bytes);
    Ok(base64_encoded)
}
