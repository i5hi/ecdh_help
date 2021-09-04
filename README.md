# ecdsa_help

We are attempting to use secp256k1 to create an ecdsa shared_secret.

Two implementations, one in rust and one in javascript, using the same keys are currently producing different results. 

Within each language, the implementations result in the same shared secret given a certain set of alice and bob keys. However, the resulting shared_secret is different across implementations.


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
