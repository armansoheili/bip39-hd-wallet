#!/usr/bin/env python3
"""
bip39-hd-wallet: BIP39 mnemonic -> BIP32 HD key derivation -> Ethereum address.

Pure Python, standard library only (hashlib, hmac, secrets, argparse).
Includes a self-contained Keccak-256 (Ethereum's hash) and secp256k1 math.

Educational tool — audit it yourself before trusting it with real funds.
"""

import argparse
import hashlib
import hmac
import os
import secrets

# ---------------------------------------------------------------------------
# Keccak-256 (Ethereum's hash function, NOT NIST SHA3 which uses suffix 0x06)
# ---------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1


def _rot(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK64


_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_KECCAK_RHO = [  # rotation offset r[x][y] per lane (FIPS 202, Table 2)
    [0, 36, 3, 41, 18],    # x = 0, y = 0..4
    [1, 44, 10, 45, 2],    # x = 1
    [62, 6, 43, 15, 61],   # x = 2
    [28, 55, 25, 21, 56],   # x = 3
    [27, 20, 39, 8, 14],   # x = 4
]


def _keccak_f1600(a):
    for rc in _KECCAK_RC:
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rot(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] ^= d[x]
        # rho + pi: B[y, (2x+3y) mod 5] = ROT(A[x, y], r[x][y])
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rot(a[x + 5 * y],
                                                       _KECCAK_RHO[x][y])
        a[:] = b
        # chi
        for y in range(5):
            row = [a[x + 5 * y] for x in range(5)]
            for x in range(5):
                a[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5]) & _MASK64
        # iota
        a[0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Keccak-256 digest of data (the hash Ethereum uses, not NIST SHA3)."""
    block = 136  # rate for 256-bit output
    state = [0] * 25
    msg = bytearray(data)
    msg.append(0x01)  # Keccak domain suffix
    while len(msg) % block:
        msg.append(0x00)
    msg[-1] |= 0x80
    for off in range(0, len(msg), block):
        for i in range(block // 8):
            lane = int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], "little")
            state[i] ^= lane
        _keccak_f1600(state)
    return b"".join(s.to_bytes(8, "little") for s in state)[:32]


# ---------------------------------------------------------------------------
# secp256k1 elliptic-curve math
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if y1 != y2:
            return None
        lam = (3 * x1 * x1) * pow(2 * y1, _P - 2, _P) % _P  # doubling
    else:
        lam = (y2 - y1) * pow(x2 - x1, _P - 2, _P) % _P  # addition
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _point_mul(k, p):
    r = None
    while k:
        if k & 1:
            r = _point_add(r, p)
        p = _point_add(p, p)
        k >>= 1
    return r


def privkey_to_pubkey(priv: int):
    """Return uncompressed (x, y) public-key point for a private key."""
    return _point_mul(priv, _G)


def eth_address_from_privkey(priv: int) -> str:
    """Derive the 0x... Ethereum address from a private key."""
    x, y = privkey_to_pubkey(priv)
    digest = keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))
    return "0x" + digest[-20:].hex()


# ---------------------------------------------------------------------------
# BIP39 (mnemonic)
# ---------------------------------------------------------------------------

_WORDLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "wordlist.txt")


def load_wordlist(path=_WORDLIST_PATH):
    with open(path, encoding="utf-8") as f:
        words = [w.strip() for w in f if w.strip()]
    if len(words) != 2048:
        raise ValueError(f"expected 2048 BIP39 words, got {len(words)}")
    return words


WORDS = load_wordlist()


def mnemonic_is_valid(mnemonic: str) -> bool:
    """Check word count, wordlist membership, and BIP39 checksum."""
    words = mnemonic.strip().split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    try:
        idx = [WORDS.index(w) for w in words]
    except ValueError:
        return False
    bits = "".join(f"{i:011b}" for i in idx)
    cs_len = len(words) // 3
    entropy_bits, checksum_bits = bits[:-cs_len], bits[-cs_len:]
    entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big")
    digest = hashlib.sha256(entropy).digest()
    expected = "".join(f"{b:08b}" for b in digest)[:cs_len]
    return checksum_bits == expected


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP39 seed: PBKDF2-HMAC-SHA512, 2048 rounds, salt 'mnemonic'+passphrase."""
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic.encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"), 2048)


def generate_mnemonic(strength: int = 128) -> str:
    """Generate a fresh random mnemonic (12/15/18/21/24 words from 128-256 bits)."""
    if strength not in (128, 160, 192, 224, 256):
        raise ValueError("strength must be one of 128/160/192/224/256")
    entropy = secrets.token_bytes(strength // 8)
    digest = hashlib.sha256(entropy).digest()
    bits = "".join(f"{b:08b}" for b in entropy + digest)
    n_words = (strength + strength // 32) // 11
    bits = bits[:n_words * 11]
    return " ".join(WORDS[int(bits[i * 11:(i + 1) * 11], 2)]
                    for i in range(n_words))


# ---------------------------------------------------------------------------
# BIP32 (hierarchical deterministic derivation)
# ---------------------------------------------------------------------------

_HARDENED = 0x80000000


def _hmac_sha512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha512).digest()


def master_key(seed: bytes):
    """BIP32 master (private key, chain code) from a BIP39 seed."""
    i = _hmac_sha512(b"Bitcoin seed", seed)
    priv = int.from_bytes(i[:32], "big")
    if priv == 0 or priv >= _N:
        raise ValueError("invalid master key (try another seed)")
    return priv, i[32:]


def _compressed_pubkey(priv: int) -> bytes:
    x, y = privkey_to_pubkey(priv)
    return (b"\x02" if y % 2 == 0 else b"\x03") + x.to_bytes(32, "big")


def ckd_priv(parent_priv: int, parent_chain: bytes, index: int):
    """Child key derivation (BIP32). Index >= 0x80000000 is hardened."""
    if index >= _HARDENED:
        data = b"\x00" + parent_priv.to_bytes(32, "big")
    else:
        data = _compressed_pubkey(parent_priv)
    data += index.to_bytes(4, "big")
    i = _hmac_sha512(parent_chain, data)
    il = int.from_bytes(i[:32], "big")
    if il >= _N:
        raise ValueError("invalid child key (try the next index)")
    child_priv = (il + parent_priv) % _N
    if child_priv == 0:
        raise ValueError("invalid child key (try the next index)")
    return child_priv, i[32:]


def parse_path(path: str):
    """Parse e.g. m/44'/60'/0'/0/0 into BIP32 indices."""
    if not path.startswith("m/"):
        raise ValueError("path must start with 'm/'")
    out = []
    for part in path[2:].split("/"):
        hardened = part.endswith(("'", "h"))
        if hardened:
            part = part[:-1]
        out.append(int(part) | (_HARDENED if hardened else 0))
    return out


def derive_path(master_priv: int, master_chain: bytes, path: str):
    priv, chain = master_priv, master_chain
    for index in parse_path(path):
        priv, chain = ckd_priv(priv, chain, index)
    return priv, chain


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

TEST_MNEMONIC = " ".join(["abandon"] * 11 + ["about"])
EXPECTED_ADDRESS = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
DEFAULT_PATH = "m/44'/60'/0'/0/0"


def main():
    ap = argparse.ArgumentParser(
        description="Derive an Ethereum address from a BIP39 mnemonic (BIP32).")
    ap.add_argument("--mnemonic",
                    default=TEST_MNEMONIC,
                    help="BIP39 mnemonic (default: official test vector)")
    ap.add_argument("--path", default=DEFAULT_PATH,
                    help="derivation path (default: m/44'/60'/0'/0/0)")
    ap.add_argument("--generate", action="store_true",
                    help="generate a fresh random 12-word mnemonic instead")
    args = ap.parse_args()

    mnemonic = generate_mnemonic() if args.generate else args.mnemonic

    if not mnemonic_is_valid(mnemonic):
        raise SystemExit("ERROR: invalid mnemonic (word count, words, or checksum)")
    print("mnemonic OK (checksum valid)")
    print("mnemonic:", mnemonic)

    seed = mnemonic_to_seed(mnemonic)
    print("seed:", seed.hex()[:32] + "...")

    mpriv, mchain = master_key(seed)
    priv, _ = derive_path(mpriv, mchain, args.path)
    address = eth_address_from_privkey(priv)

    print("path:", args.path)
    print("private key:", f"{priv:064x}")
    print("address:", address)

    # self-test against the official BIP39/BIP44 vector
    if mnemonic == TEST_MNEMONIC and args.path == DEFAULT_PATH:
        assert address.lower() == EXPECTED_ADDRESS.lower(), "self-test FAILED"
        print("self-test passed: matches official test vector")


if __name__ == "__main__":
    main()
