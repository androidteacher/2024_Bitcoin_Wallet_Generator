import ecdsa
import hashlib
import os
from Crypto.Hash import RIPEMD160  # Import RIPEMD160 from pycryptodome

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n % 58] + result
        n //= 58  # Use integer division
    return result

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + c
    return result

def countLeadingChars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count

# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version, payload):
    s = bytes([version]) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[:4]
    result = s + checksum
    leadingZeros = countLeadingChars(result, 0)
    return '1' * leadingZeros + base58encode(base256decode(result))

def privateKeyToWif(key_hex):
    return base58CheckEncode(0x80, bytes.fromhex(key_hex))

def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(s), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return (b'\04' + vk.to_string()).hex()

def pubKeyToAddr(s):
    sha256_hash = hashlib.sha256(bytes.fromhex(s)).digest()
    ripemd160_hash = RIPEMD160.new(sha256_hash).digest()
    return base58CheckEncode(0, ripemd160_hash)

def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))

# Generate a random private key
private_key = os.urandom(32).hex()

# Uncomment the following line to use a specific private key
# private_key = "0000000000000000000000000000000000000000000000000000000000000001"

print("private key:", privateKeyToWif(private_key))
print("public key:", keyToAddr(private_key))
