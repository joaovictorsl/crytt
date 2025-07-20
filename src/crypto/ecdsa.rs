use p256::ecdsa::{SigningKey, VerifyingKey}; 
use rand::rngs::OsRng;

use crate::crypto::KeyPair;

#[derive(Debug)]
pub struct EcdsaKeyPair {
    pub pkey: VerifyingKey,
    pub skey: SigningKey,
}

impl KeyPair for EcdsaKeyPair {
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;

    fn new(
        pkey: Self::PublicKey,
        skey: Self::PrivateKey,
    ) -> Self {
        EcdsaKeyPair { pkey, skey }
    }

    fn pkey(&self) -> &Self::PublicKey {
        &self.pkey
    }

    fn skey(&self) -> &Self::PrivateKey {
        &self.skey
    }
}

pub fn generate_keypair() -> impl KeyPair {
    let skey = SigningKey::random(&mut OsRng);
    let pkey = VerifyingKey::from(&skey);
    EcdsaKeyPair { pkey, skey }
}
