const bip32  = require("bip32");
const { expect } = require("chai");
const crypto = require("crypto");
const mocha = require("mocha");


function extract_ecdsa_pair(extended_keys){
 
    const parent_key = bip32.fromBase58(extended_keys.xprv);
    
    const ecdsa_keys = {
      private_key: parent_key.privateKey.toString("hex"),
      public_key: parent_key.publicKey.toString("hex")
    };
    return ecdsa_keys;
    
}

function calculate_shared_secret(ecdsa_keys) {
  const type = "secp256k1";

  let curve = crypto.createECDH(type);

  console.log({ecdsa_keys});

  curve.setPrivateKey(ecdsa_keys.private_key,"hex");
  let cpub = curve.getPublicKey("hex","compressed");
  
  const shared_secret = curve.computeSecret(crypto.ECDH.convertKey(
    ecdsa_keys.public_key,
    type,
    "hex",
    "hex",
    "uncompressed").toString("hex"),"hex");
    
  return shared_secret.toString("hex");
}

let alice_xkeys = {
  xprv: "xprvA3nH6HUGxEUZbeZ2AGbsuVcsoEsa269AmySR95i3E81mwY3TmWoxoGUUqB59p8kjS6wb3Ppg2c9y3vKyG2aecijRpJfGWMxVX4swXwMLaSB", 
  xpub: "xpub6GmdVo1Anc2rp8dVGJ8tGdZcMGi4RYs29CN1wU7enTYkpLNcK48DM4nxgTLoSCEfGYGJZ6JqPwCpSnoGfEwDUU6tszeSUcdEqntoqqRCLhm"
};
let bob_xkeys = {
  xprv: "xprvA19Tn2HMUhBxgBux1vuQFJ8dqn1CHoNJfEGdfW86jbWQJE1t1RXsaBit71vbw8QKhKGZUyo4yGpA3WfsgTxS3MwrTSjuorWy3ajM4VLhvDM", 
  xpub: "xpub6E8pBXpFK4kFtfzR7xSQcS5NPoqghG6A2TCETtXiHw3PB2M2Yxr87z3MxFmMfhkPjdhdNPLXwEZzPKqYueiDXgREhVqCkdoxYMCub9cjhoN"
};

let alice_pair =  {
  private_key: "3c842fc0e15f2f1395922d432aafa60c35e09ad97c363a37b637f03e7adcb1a7",
  public_key: "02dfbbf1979269802015da7dba4143ff5935ea502ef3a7276cc650be0d84a9c882",
};


const bob_pair =  {
  private_key: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0",
  public_key: "023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d",
};

let expected_shared_secret = "49ab8cb9ba741c6083343688544861872e3b73b3d094b09e36550cf62d06ef1e";



it("should extract_ecdsa_pair from extended key pair", async function () {
  let key_pair = extract_ecdsa_pair(alice_xkeys);
  if (key_pair instanceof Error) throw key_pair;
  expect(key_pair.public_key).to.equal(alice_pair.public_key);
  expect(key_pair.private_key).to.equal(alice_pair.private_key);

  key_pair = extract_ecdsa_pair(bob_xkeys);
  if (key_pair instanceof Error) throw key_pair;
  expect(key_pair.public_key).to.equal(bob_pair.public_key);
  expect(key_pair.private_key).to.equal(bob_pair.private_key);
});
it("should generate_shared_secret from alice public_key and bob private_key", async function () {
  
  let shared_secret_0 = calculate_shared_secret({private_key: alice_pair.private_key, public_key: bob_pair.public_key});
  let shared_secret_1 = calculate_shared_secret({private_key: bob_pair.private_key, public_key: alice_pair.public_key});
  console.log({shared_secret_0});
  expect(shared_secret_0).to.equal(shared_secret_1);
  expect(shared_secret_0).to.equal(expected_shared_secret);

});
