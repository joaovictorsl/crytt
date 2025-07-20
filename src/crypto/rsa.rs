use rsa::{
    RsaPrivateKey, RsaPublicKey
};
use rand::rngs::OsRng;

use crate::crypto::{Error, KeyPair};

#[derive(Debug)]
pub struct RsaKeyPair {
    pub pkey: RsaPublicKey,
    pub skey: RsaPrivateKey,
}

impl KeyPair for RsaKeyPair {
    type PrivateKey = RsaPrivateKey;
    type PublicKey = RsaPublicKey;

    fn new(
        pkey: Self::PublicKey,
        skey: Self::PrivateKey,
    ) -> Self {
        RsaKeyPair { pkey, skey }
    }

    fn pkey(&self) -> &Self::PublicKey {
        &self.pkey
    }

    fn skey(&self) -> &Self::PrivateKey {
        &self.skey
    }
}

pub fn generate_keypair(bits: usize) -> Result<impl KeyPair, Error> {
    let mut rng = OsRng;
    let skey: RsaPrivateKey;
    match RsaPrivateKey::new(&mut rng, bits) {
        Ok(key) => {
            skey = key;
        },
        Err(err) => return Err(Error::GenerateKeyPairError(err.to_string())),
    }
    let pkey = RsaPublicKey::from(&skey);

    Ok(RsaKeyPair { pkey, skey })
}
