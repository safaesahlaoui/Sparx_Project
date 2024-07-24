# sparx_crypto.py

from sparx_func import modular_add, modular_sub, sparx_sbox, sparx_sbox_inv, sparx_pbox, sparx_pbox_inv, key_schedule
import base64

def sparx_round(x, k):
    x1, x2 = x
    x1 = modular_add(x1, k)
    x1 = sparx_sbox(x1)
    x2 = sparx_pbox(x2)
    x2 = modular_add(x2, x1)
    return x1, x2

def sparx_round_inv(x, k):
    x1, x2 = x
    x2 = modular_sub(x2, x1)
    x2 = sparx_pbox_inv(x2)
    x1 = sparx_sbox_inv(x1)
    x1 = modular_sub(x1, k)
    return x1, x2

def sparx_encrypt_block(block, key_schedule):
    x = block
    for k in key_schedule:
        x = sparx_round(x, k)
    return x

def sparx_decrypt_block(block, key_schedule):
    x = block
    for k in reversed(key_schedule):
        x = sparx_round_inv(x, k)
    return x

def text_to_blocks(text):
    blocks = []
    for i in range(0, len(text), 2):
        blocks.append((ord(text[i]), ord(text[i + 1]) if i + 1 < len(text) else 0))
    return blocks

def blocks_to_text(blocks):
    text = ''
    for block in blocks:
        for char_code in block:
            try:
                text += chr(char_code)
            except ValueError:
                text += '?'
    return text

def sparx_encrypt(plain_text, key):
    key_schedule_ = key_schedule(key)
    blocks = text_to_blocks(plain_text)
    encrypted_blocks = [sparx_encrypt_block(block, key_schedule_) for block in blocks]
    encrypted_bytes = b''.join(block.to_bytes(2, 'big') for block_pair in encrypted_blocks for block in block_pair)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def sparx_decrypt(cipher_text, key):
    encrypted_bytes = base64.b64decode(cipher_text.encode('utf-8'))
    blocks = [(int.from_bytes(encrypted_bytes[i:i+2], 'big'), int.from_bytes(encrypted_bytes[i+2:i+4], 'big')) for i in range(0, len(encrypted_bytes), 4)]
    key_schedule_ = key_schedule(key)
    decrypted_blocks = [sparx_decrypt_block(block, key_schedule_) for block in blocks]
    return blocks_to_text(decrypted_blocks)
