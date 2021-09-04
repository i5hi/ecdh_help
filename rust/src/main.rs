use std::str::FromStr;
use std::str;
use secp256k1::{SecretKey, PublicKey,ecdh::SharedSecret};
use bip32::{XPrv, XPub};


/// Derive the ECDSA key pair from extended key pair
pub fn extract_ecdsa_pair(extended_keypair: (&str,&str))->Result<(SecretKey,PublicKey),String>{
  let signing_key = match XPrv::from_str(&extended_keypair.0){
    Ok(xprv)=>xprv.private_key().to_bytes(),
    Err(_)=>return Err("Broke while parsing extended private key".to_string())
  };

  let verification_key = XPub::from_str(&extended_keypair.1).unwrap().public_key().to_bytes();
  Ok((SecretKey::from_slice(&signing_key).unwrap(), PublicKey::from_slice(&verification_key).unwrap()))
}

/// Generate a ecdsa shared secret
pub fn generate_shared_secret(secret_key: SecretKey, public_key: PublicKey)->Result<SharedSecret,String>{
  Ok(SharedSecret::new(&public_key, &secret_key))
} 

#[cfg(test)]
mod test{
  use super::*;
  use std::fmt::Display;
  
  #[test]
  fn isolated_extract_ecdsa(){
    let xkeys = (
      "xprvA3nH6HUGxEUZbeZ2AGbsuVcsoEsa269AmySR95i3E81mwY3TmWoxoGUUqB59p8kjS6wb3Ppg2c9y3vKyG2aecijRpJfGWMxVX4swXwMLaSB", 
      "xpub6GmdVo1Anc2rp8dVGJ8tGdZcMGi4RYs29CN1wU7enTYkpLNcK48DM4nxgTLoSCEfGYGJZ6JqPwCpSnoGfEwDUU6tszeSUcdEqntoqqRCLhm"
    );

    let ecdsa = extract_ecdsa_pair(xkeys).unwrap();
    println!("NOTICE String: {:#?}",&ecdsa);
    println!("NOTICE String: {:#?}",&ecdsa.1.to_string());
    println!("ABOVE IS THE SAME AS BELOW");
    println!("NOTICE PublicKey: {:#?}",PublicKey::from_str(&ecdsa.1.to_string()).unwrap());
    let expected_pair =  (
      "3c842fc0e15f2f1395922d432aafa60c35e09ad97c363a37b637f03e7adcb1a7".to_string(),
      "02dfbbf1979269802015da7dba4143ff5935ea502ef3a7276cc650be0d84a9c882".to_string(),
    );

    assert_eq!(expected_pair,(ecdsa.0.to_string(), ecdsa.1.to_string()));
    
    let xkeys = (
      "xprvA19Tn2HMUhBxgBux1vuQFJ8dqn1CHoNJfEGdfW86jbWQJE1t1RXsaBit71vbw8QKhKGZUyo4yGpA3WfsgTxS3MwrTSjuorWy3ajM4VLhvDM", 
      "xpub6E8pBXpFK4kFtfzR7xSQcS5NPoqghG6A2TCETtXiHw3PB2M2Yxr87z3MxFmMfhkPjdhdNPLXwEZzPKqYueiDXgREhVqCkdoxYMCub9cjhoN"
    );

    let ecdsa = extract_ecdsa_pair(xkeys).unwrap();
    println!("NOTICE String: {:#?}",&ecdsa);

    println!("NOTICE String: {:#?}",&ecdsa.1.to_string());
    println!("ABOVE IS THE SAME AS BELOW");
    println!("NOTICE PublicKey: {:#?}",PublicKey::from_str(&ecdsa.1.to_string()).unwrap());
    let expected_pair =  (
      "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0".to_string(),
      "023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d".to_string(),
    );

    assert_eq!(expected_pair,(ecdsa.0.to_string(), ecdsa.1.to_string()))
  }

  #[test]
  fn isolated_shared_secret(){
    let alice_pair =  (
      SecretKey::from_str("d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0").unwrap(),
      PublicKey::from_str("023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d").unwrap(),
    );

    let bob_pair =  (
      SecretKey::from_str("3c842fc0e15f2f1395922d432aafa60c35e09ad97c363a37b637f03e7adcb1a7").unwrap(),
      PublicKey::from_str("02dfbbf1979269802015da7dba4143ff5935ea502ef3a7276cc650be0d84a9c882").unwrap(),
    ); 

    let expected_shared_secret = "49ab8cb9ba741c6083343688544861872e3b73b3d094b09e36550cf62d06ef1e";

    let alice_shared_secret = generate_shared_secret(alice_pair.0, bob_pair.1).unwrap();
    let bob_shared_secret = generate_shared_secret(bob_pair.0, alice_pair.1).unwrap();

    assert_eq!(alice_shared_secret.as_ref(),bob_shared_secret.as_ref());
    assert_eq!(format!("{:#?}",alice_shared_secret),expected_shared_secret)

  }


}

fn main() {
    println!("Hello, world!");
}
