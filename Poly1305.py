import ChaCha20
import math


def clamp(r):
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    return r


def int_to_tag(acc):
    acc %= 1 << 128
    s = hex(acc)[2:].zfill(32)
    return ":".join([s[i:i+2] for i in range(0, len(s), 2)][::-1])


def poly1305_mac(msg, key):
    r = int.from_bytes(key[:16], byteorder="little")
    r = clamp(r)
    s = int.from_bytes(key[16:], byteorder="little")
    acc = 0
    p = (1 << 130)-5
    for i in range(1, math.ceil(len(msg)/16)+1):
        n = int.from_bytes(
            msg[((i-1)*16):(i*16)] + b'\x01', byteorder="little")
        acc += n
        acc = (r * acc) % p
    acc += s
    return int_to_tag(acc)


def poly1305_key_gen(key, nonce):
    counter = 0
    block = ChaCha20.ChaCha20Block(key, counter, nonce)
    return block[:32]
