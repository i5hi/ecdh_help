# ecdsa_help

We are attempting to use secp256k1 to create an ecdsa shared_secret.

Three implementations, one in rust, one in javascript and one in python, using the same keys are currently producing different results. 

javacript and python produce the same shared_secret while rust produces a different result.

## rust

```
cd rust/src
cargo test -- --nocapture
```

SHARED_SECRET RESULT : 49ab8cb9ba741c6083343688544861872e3b73b3d094b09e36550cf62d06ef1e
 
## javascript
```
cd javascript
npm install
npm test
```

SHARED_SECRET RESULT : 48c413dc9459a3c154221a524e8fad34267c47fc7b47443246fa8919b19fff93

## python

```
cd python
pip install ecdsa
python3 main.py
```

SHARED_SECRET RESULT : 48c413dc9459a3c154221a524e8fad34267c47fc7b47443246fa8919b19fff93
