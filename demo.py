#!/usr/bin/env python3
import AEAD_CHACHA20_POLY1305
import utils
import binascii

"""
    Demo script for AEAD with ChaCha20 and Poly1305
    key, iv and const play the same roles as described in
    RFC8439 and should be given as string of the following format:
    byte:byte:byte:byte ...
    aad and plaintext shall be given as bytes
"""


def demo(aad, key, iv, const, plaintext):
    key = utils.unpack(key)
    iv = utils.unpack(iv)
    const = utils.unpack(const)
    (AEAD_construction, ciphertext, tag) = AEAD_CHACHA20_POLY1305.AEAD(
        aad, key, iv, const, plaintext)
    print("########~ENCRYPTION~########")
    print("AEAD construction printed in ./demo/AEAD_Construction")
    print("Ciphertext printed in ./demo/ciphertext")
    print(f"Tag:\n{tag}")
    with open("demo/AEAD_Construction", "wb") as f:
        f.write(AEAD_construction)
    with open("demo/ciphertext", "wb") as f:
        f.write(ciphertext)
    print("########~DECRYPTION~########")
    (plaintext, tag_validation) = AEAD_CHACHA20_POLY1305.chacha20_aead_decrypt(
        aad, key, iv, const, ciphertext, tag)
    print(f"Decrypted plaintext:\n{plaintext.decode()}")
    print(f"Authentication status: {tag_validation}")


if __name__ == "__main__":
    key = '80:81:82:83:84:85:86:87:88:89:8a:8b:8c:8d:8e:8f:90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:9f'
    iv = '40:41:42:43:44:45:46:47'
    const = '07:00:00:00'
    aad = b"\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7"
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".encode()

    demo(aad, key, iv, const, plaintext)
