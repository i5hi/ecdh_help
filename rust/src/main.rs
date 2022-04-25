use std::str::{FromStr};
use secp256k1::Secp256k1;
use secp256k1::{ecdh::SharedSecret, KeyPair, PublicKey, SecretKey, XOnlyPublicKey};
use bitcoin::util::bip32::ExtendedPrivKey;

#[derive(Debug)]
pub struct XOnlyPair {
  pub seckey: String,
  pub pubkey: String,
}
impl XOnlyPair {
  pub fn from_keypair(keypair: KeyPair) -> Result<Self,String> {
    let pubkey = match XOnlyPublicKey::from_str(&keypair.public_key().to_string()) {
      Ok(result) => result,
      Err(_) =>  return Err("BAD PUBKEY STRING".to_string()),
    };

    return Ok(XOnlyPair {
      seckey: hex::encode(keypair.secret_bytes()).to_string(),
      pubkey: pubkey.to_string(),
    });
  }
}

pub fn keypair_from_xprv_str(xprv: &str) -> Result<KeyPair, String> {
  let secp = Secp256k1::new();
  let xprv = match ExtendedPrivKey::from_str(xprv) {
    Ok(result) => result,
    Err(_) => return Err("BAD XPRV STRING".to_string()),
  };

  Ok(xprv.to_keypair(&secp))
}

pub fn keypair_from_seckey_str(seckey: &str) -> Result<KeyPair, String> {
  let secp = Secp256k1::new();
  let key_pair = match KeyPair::from_seckey_str(&secp, seckey) {
    Ok(kp) => kp,
    Err(_) => return Err("BAD SECKEY STRING".to_string()),
  };
  Ok(key_pair)
}

/// Generate a ecdsa shared secret
pub fn compute_shared_secret_str(
  secret_key: &str, 
  public_key: &str
) -> Result<String, String> {
  let seckey = match SecretKey::from_str(secret_key) {
    Ok(result) => result,
    Err(_) =>  return Err("BAD SECKEY STRING".to_string()),
  };
  let public_key = if public_key.clone().len() == 64 {
    "02".to_string() + public_key.clone()
  } else if public_key.clone().len() == 66 {
    public_key.to_string()
  } else {
     return Err("BAD PUBKEY STRING".to_string());
  };
  let pubkey = match PublicKey::from_str(&public_key) {
    Ok(result) => result,
    Err(_) =>  return Err("BAD PUBKEY STRING".to_string()),
  };
  let shared_secret = SharedSecret::new(&pubkey, &seckey);
  let shared_secret_hex = hex::encode(&(shared_secret.secret_bytes()));
  Ok(shared_secret_hex)
}


#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_from_xprv_str() {
    let xprv= "xprv9ym1fn2sRJ6Am4z3cJkM4NoxFsaeNdSyFQvE5CqzqqterM5nZdKUStQghQWBupjAgJZEgAWCSQWuFgqbvdGwg22tiUp8rsupd4fTrtYMEWS";
    let key_pair = keypair_from_xprv_str(xprv).unwrap();
    let expected_pubkey = "86a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f";
    assert_eq!(expected_pubkey, key_pair.public_key().to_string());
  }
  #[test]
  fn test_shared_secret() {
    let alice_pair = XOnlyPair {
      seckey: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0".to_string(),
      pubkey: "3946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d".to_string(),
    };
    let bob_pair = XOnlyPair {
      seckey: "3c842fc0e15f2f1395922d432aafa60c35e09ad97c363a37b637f03e7adcb1a7".to_string(),
      pubkey: "dfbbf1979269802015da7dba4143ff5935ea502ef3a7276cc650be0d84a9c882".to_string(),
    };
    let expected_shared_secret = "48c413dc9459a3c154221a524e8fad34267c47fc7b47443246fa8919b19fff93";
    let alice_shared_secret =
      compute_shared_secret_str(&alice_pair.seckey, &bob_pair.pubkey).unwrap();
    let bob_shared_secret =
      compute_shared_secret_str(&bob_pair.seckey, &alice_pair.pubkey).unwrap();
    // let alice_shared_secret = generate_shared_secret(alice_pair.0, bob_pair.1).unwrap();
    // let bob_shared_secret = generate_shared_secret(bob_pair.0, alice_pair.1).unwrap();
    assert_eq!(alice_shared_secret, bob_shared_secret);
    assert_eq!(alice_shared_secret,expected_shared_secret);
  }
}

fn main() {
  print!("Hi");
}