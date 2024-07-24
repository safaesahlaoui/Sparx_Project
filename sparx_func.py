# sparx_func.py

import hashlib

def modular_add(a, b):
    return (a + b) % (2 ** 16)

def modular_sub(a, b):
    return (a - b) % (2 ** 16)

def sparx_sbox(x):
    return ((x * 3) + 5) % (2 ** 16)

def sparx_sbox_inv(y):
    return ((y - 5) * pow(3, -1, 2**16)) % (2 ** 16)

def sparx_pbox(x):
    return ((x << 7) | (x >> (16 - 7))) % (2 ** 16)

def sparx_pbox_inv(y):
    return ((y >> 7) | (y << (16 - 7))) % (2 ** 16)

def key_schedule(key):
    hash_obj = hashlib.sha256(key.encode())
    hash_bytes = hash_obj.digest()
    key_schedule = [int.from_bytes(hash_bytes[i:i+2], 'big') for i in range(0, len(hash_bytes), 2)]
    return key_schedule
