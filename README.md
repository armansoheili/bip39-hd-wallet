# bip39-hd-wallet

BIP39 mnemonic → BIP32 hierarchical-deterministic key derivation → Ethereum
address, in **pure Python** (standard library only — no dependencies).

Everything is implemented from scratch in one file:

- **Keccak-256** — Ethereum's hash function (not NIST SHA3), full
  Keccak-f[1600] sponge
- **secp256k1** — elliptic-curve math (point addition / scalar multiplication)
- **BIP39** — mnemonic checksum validation, `PBKDF2-HMAC-SHA512` seed
  derivation, random mnemonic generation
- **BIP32** — master key from seed, hardened & normal child derivation,
  path parsing (`m/44'/60'/0'/0/0`)

The official BIP39 English wordlist ships as `wordlist.txt`.

## Usage

```bash
# derive from the default (official BIP39 test vector) mnemonic
python3 hd_wallet.py

# your own mnemonic and path
python3 hd_wallet.py --mnemonic "word1 word2 ... word12" --path "m/44'/60'/0'/0/1"

# generate a fresh random 12-word mnemonic and derive from it
python3 hd_wallet.py --generate
```

Example output:

```
mnemonic OK (checksum valid)
mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
seed: 5eb00bbddcf069084889a8ab91555681...
path: m/44'/60'/0'/0/0
private key: 1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727
address: 0x9858effd232b4033e47d90003d41ec34ecaeda94
self-test passed: matches official test vector
```

The run ends with a self-test: the well-known `abandon … about` vector must
derive seed `5eb00bbd…`, private key `1ab42cc4…` and address
`0x9858effd…eda94` — it does.

> Educational project. The cryptography here is standard, but audit anything
> before trusting it with real funds.
