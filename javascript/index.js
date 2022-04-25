const secp256k1 = require('@noble/secp256k1');
const bip32  = require("bip32");
const { expect } = require("chai");
const crypto = require("crypto");
const mocha = require("mocha");

function extract_ecdsa_pair(extended_keys) {
    const parent_key = bip32.fromBase58(extended_keys.xprv);
    const pubkey = secp256k1.schnorr.getPublicKey(parent_key.privateKey.toString("hex"));
    const ecdsa_keys = {
      privkey: parent_key.privateKey.toString("hex"),
      pubkey: Buffer.from(pubkey).toString('hex')
    };
    return ecdsa_keys;
}

function calculate_shared_secret(ecdsa_keys) {
  ecdsa_keys.pubkey= (ecdsa_keys.pubkey.startsWith("02" || "03"))?ecdsa_keys.pubkey:"02"+ecdsa_keys.pubkey;
  return Buffer.from(secp256k1.getSharedSecret(ecdsa_keys.privkey,ecdsa_keys.pubkey, true)).toString('hex').slice(2)
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
  privkey: "3c842fc0e15f2f1395922d432aafa60c35e09ad97c363a37b637f03e7adcb1a7",
  pubkey: "dfbbf1979269802015da7dba4143ff5935ea502ef3a7276cc650be0d84a9c882",
};

const bob_pair =  {
  privkey: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0",
  pubkey: "3946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d",
};

let expected_shared_secret = "48c413dc9459a3c154221a524e8fad34267c47fc7b47443246fa8919b19fff93";


it("should extract_ecdsa_pair from extended key pair", async function () {
  let key_pair = extract_ecdsa_pair(alice_xkeys);
  if (key_pair instanceof Error) throw key_pair;
  console.log({key_pair})

  expect(key_pair.pubkey).to.equal(alice_pair.pubkey);
  expect(key_pair.privkey).to.equal(alice_pair.privkey);

  console.log({key_pair})
  key_pair = extract_ecdsa_pair(bob_xkeys);
  if (key_pair instanceof Error) throw key_pair;
  expect(key_pair.pubkey).to.equal(bob_pair.pubkey);
  expect(key_pair.privkey).to.equal(bob_pair.privkey);
});

it("should generate_shared_secret from alice pubkey and bob privkey", async function () {
  let shared_secret_0 = calculate_shared_secret({privkey: alice_pair.privkey, pubkey: bob_pair.pubkey});
  let shared_secret_1 = calculate_shared_secret({privkey: bob_pair.privkey, pubkey: alice_pair.pubkey});
  console.log({shared_secret_0});
  expect(shared_secret_0).to.equal(shared_secret_1);
  expect(shared_secret_0).to.equal(expected_shared_secret);
});
