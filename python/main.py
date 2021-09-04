from ecdsa import ECDH, SECP256k1, SigningKey, VerifyingKey
from binascii import unhexlify

def calculate_shared_secret(local_private_key,remote_public_key):
  ecdh = ECDH(curve=SECP256k1)
  sk = SigningKey.from_string(bytes.fromhex(local_private_key), curve=SECP256k1)
  vk = VerifyingKey.from_string(bytes.fromhex(remote_public_key), curve=SECP256k1)
  
  ecdh.load_private_key(sk)
  ecdh.load_received_public_key(vk)
  sharedsecret = ecdh.generate_sharedsecret()
  return hex(sharedsecret)

alice_private="d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0"
alice_public="023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d"

bob_private="3c842fc0e15f2f1395922d432aafa60c35e09ad97c363a37b637f03e7adcb1a7"
bob_public="02dfbbf1979269802015da7dba4143ff5935ea502ef3a7276cc650be0d84a9c882"

rust_shared_secret="0x49ab8cb9ba741c6083343688544861872e3b73b3d094b09e36550cf62d06ef1e"
js_shared_secret="0x48c413dc9459a3c154221a524e8fad34267c47fc7b47443246fa8919b19fff93"

# print(hex(calculate_shared_secret(alice_private,bob_public)))
assert calculate_shared_secret(alice_private,bob_public) == calculate_shared_secret(bob_private,alice_public)
assert calculate_shared_secret(alice_private,bob_public) == js_shared_secret
