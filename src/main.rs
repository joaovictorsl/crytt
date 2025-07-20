mod crypto;
use crypto::{rsa, ecdsa};

const RSA_SIZE: usize = 2048;
const RSA_SKEY_FILE: &str = "rsa_key";
const RSA_PKEY_FILE: &str = "rsa_key.pub";
const ECDSA_SKEY_FILE: &str = "ecdsa_key";
const ECDSA_PKEY_FILE: &str = "ecdsa_key.pub";

fn main() {
    let ecdsa_keypair = match crypto::load_keypair(ECDSA_SKEY_FILE, ECDSA_PKEY_FILE) {
        Ok(kp) => kp,
        Err(_) => {
            let kp = ecdsa::generate_keypair();
            crypto::export_keypair_to_file(&kp, ECDSA_SKEY_FILE, ECDSA_PKEY_FILE).unwrap();
            kp
        }
    };

    let rsa_keypair = match crypto::load_keypair(RSA_SKEY_FILE, RSA_PKEY_FILE) {
        Ok(kp) => kp,
        Err(_) => {
            let kp = rsa::generate_keypair(RSA_SIZE).unwrap();
            crypto::export_keypair_to_file(&kp, RSA_SKEY_FILE, RSA_PKEY_FILE).unwrap();
            kp
        }
    };

    crypto::export_keypair_to_file(&rsa_keypair, RSA_SKEY_FILE, RSA_PKEY_FILE).unwrap();
    crypto::export_keypair_to_file(&ecdsa_keypair, RSA_SKEY_FILE, RSA_PKEY_FILE).unwrap();
}
