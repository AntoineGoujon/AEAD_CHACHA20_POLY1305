import ChaCha20
import Poly1305


def pad16(x):
    if (len(x) % 16 == 0):
        return b''
    else:
        return b'\x00' * (16 - (len(x) % 16))


def chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
    nonce = constant + iv
    otk = Poly1305.poly1305_key_gen(key, nonce)
    ciphertext = ChaCha20.ChaCha20Encrypt(key, 1, nonce, plaintext)
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += (len(aad)).to_bytes(8, "little")
    mac_data += (len(ciphertext)).to_bytes(8, "little")
    tag = Poly1305.poly1305_mac(mac_data, otk)
    return (ciphertext, tag)


def chacha20_aead_decrypt(aad, key, iv, constant, ciphertext, tag):
    nonce = constant + iv
    otk = Poly1305.poly1305_key_gen(key, nonce)
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += (len(aad)).to_bytes(8, "little")
    mac_data += (len(ciphertext)).to_bytes(8, "little")
    tag_validation = tag == Poly1305.poly1305_mac(mac_data, otk)
    if tag_validation:
        plaintext = ChaCha20.ChaCha20Encrypt(key, 1, nonce, ciphertext)
    else:
        plaintext = b'invalid tag'
    return (plaintext, tag_validation)


def AEAD(aad, key, iv, constant, plaintext):
    (ciphertext, tag) = chacha20_aead_encrypt(
        aad, key, iv, constant, plaintext)
    AEAD_construction = aad + pad16(aad)
    AEAD_construction += ciphertext + pad16(ciphertext)
    AEAD_construction += (len(aad)).to_bytes(8, "little")
    AEAD_construction += (len(ciphertext)).to_bytes(8, "little")
    return (AEAD_construction, ciphertext, tag)
