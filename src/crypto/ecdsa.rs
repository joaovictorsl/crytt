use base64::{Engine as _, engine::general_purpose};
use std::fs;
use std::io::{Read, Write};

use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;

use crate::crypto::errors::Error;

#[derive(Debug, Clone)]
pub struct EcdsaKeyPair {
    pub pkey: VerifyingKey,
    pub skey: SigningKey,
}

pub fn generate_keypair() -> EcdsaKeyPair {
    let skey = SigningKey::random(&mut OsRng);
    let pkey = VerifyingKey::from(&skey);

    EcdsaKeyPair { pkey, skey }
}

pub fn load_keypair(spath: &str, ppath: &str, buf: &mut Vec<u8>) -> Result<EcdsaKeyPair, Error> {
    read_file(spath, buf)?;
    let skey = skey_from_base64(buf)?;

    read_file(ppath, buf)?;
    let pkey = pkey_from_base64(buf)?;

    Ok(EcdsaKeyPair { pkey, skey })
}

fn read_file(path: &str, output: &mut Vec<u8>) -> Result<(), Error> {
    let mut file: fs::File;
    match fs::File::open(path) {
        Ok(f) => file = f,
        Err(err) => return Err(Error::LoadKeyPairError(err.to_string())),
    }

    file.read_to_end(output)
        .map_err(|e| Error::ReadFileError(format!("Failed to read file: {:?}", e)))?;
    Ok(())
}

pub fn export_keypair_to_file(
    keypair: &EcdsaKeyPair,
    spath: &str,
    ppath: &str,
) -> Result<(), Error> {
    let sexported = encode_skey_to_export(&keypair.skey)?;
    let pexported = encode_pkey_to_export(&keypair.pkey)?;

    let mut sfile = fs::File::create(spath).unwrap();
    let mut pfile = fs::File::create(ppath).unwrap();

    sfile.write_all(sexported.as_bytes()).unwrap();
    pfile.write_all(pexported.as_bytes()).unwrap();

    Ok(())
}

pub fn encode_skey_to_export(skey: &SigningKey) -> Result<String, Error> {
    let der_bytes = match skey.to_pkcs8_der() {
        Ok(res) => res.to_bytes(),
        Err(e) => return Err(Error::ExportKeyError(e.to_string())),
    };

    let base64_encoded = general_purpose::STANDARD.encode(&der_bytes);
    Ok(base64_encoded)
}

pub fn encode_pkey_to_export(pkey: &VerifyingKey) -> Result<String, Error> {
    let der_bytes = match pkey.to_public_key_der() {
        Ok(res) => res.to_vec(),
        Err(e) => return Err(Error::ExportKeyError(e.to_string())),
    };

    let base64_encoded = general_purpose::STANDARD.encode(&der_bytes);
    Ok(base64_encoded)
}

pub fn pkey_from_base64(payload: &mut Vec<u8>) -> Result<VerifyingKey, Error> {
    // Decode Base64 strings back to DER bytes
    let p_der_bytes = general_purpose::STANDARD.decode(&payload).map_err(|e| {
        Error::LoadKeyPairError(format!("Failed to base64 decode public key: {}", e))
    })?;

    let pkey = DecodePublicKey::from_public_key_der(&p_der_bytes)
        .map_err(|e| Error::LoadKeyPairError(format!("Failed to decode public key DER: {}", e)))?;

    Ok(pkey)
}

pub fn skey_from_base64(payload: &mut Vec<u8>) -> Result<SigningKey, Error> {
    // Decode Base64 strings back to DER bytes
    let s_der_bytes = general_purpose::STANDARD.decode(&payload).map_err(|e| {
        Error::LoadKeyPairError(format!("Failed to base64 decode private key: {}", e))
    })?;

    let skey = DecodePrivateKey::from_pkcs8_der(&s_der_bytes)
        .map_err(|e| Error::LoadKeyPairError(format!("Failed to decode private key DER: {}", e)))?;

    Ok(skey)
}
