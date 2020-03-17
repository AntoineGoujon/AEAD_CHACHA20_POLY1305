#!/usr/bin/env python3

import AEAD_CHACHA20_POLY1305
import Poly1305
import utils


def testPoly1305():
    key = b"\x85\xd6\xbe\x78\x57\x55\x6d\x33\x7f\x44\x52\xfe\x42\xd5\x06\xa8\x01\x03\x80\x8a\xfb\x0d\xb2\xfd\x4a\xbf\xf6\xaf\x41\x49\xf5\x1b"
    msg = "Cryptographic Forum Research Group".encode()
    tag_int = Poly1305.poly1305_mac(msg, key)
    assert tag_int == Poly1305.int_to_tag(0x2a927010caf8b2bc2c6365130c11d06a8)
    print("testPoly1305 ok")


def testKeyGen():
    key = "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f".replace(
        " ", ":")
    nonce = "00 00 00 00 00 01 02 03 04 05 06 07".replace(" ", ":")
    k = utils.unpack(key)
    n = utils.unpack(nonce)
    b = Poly1305.poly1305_key_gen(k, n)
    with open("out", "wb") as f:
        f.write(b)


def testVector4():
    key = b"\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0\x47\x39\x17\xc1\x40\x2b\x80\x09\x9d\xca\x5c\xbc\x20\x70\x75\xc0"
    msg = b'\x27\x54\x77\x61\x73\x20\x62\x72\x69\x6c\x6c\x69\x67\x2c\x20\x61\x6e\x64\x20\x74\x68\x65\x20\x73\x6c\x69\x74\x68\x79\x20\x74\x6f\x76\x65\x73\x0a\x44\x69\x64\x20\x67\x79\x72\x65\x20\x61\x6e\x64\x20\x67\x69\x6d\x62\x6c\x65\x20\x69\x6e\x20\x74\x68\x65\x20\x77\x61\x62\x65\x3a\x0a\x41\x6c\x6c\x20\x6d\x69\x6d\x73\x79\x20\x77\x65\x72\x65\x20\x74\x68\x65\x20\x62\x6f\x72\x6f\x67\x6f\x76\x65\x73\x2c\x0a\x41\x6e\x64\x20\x74\x68\x65\x20\x6d\x6f\x6d\x65\x20\x72\x61\x74\x68\x73\x20\x6f\x75\x74\x67\x72\x61\x62\x65\x2e'
    tag = Poly1305.poly1305_mac(msg, key)
    assert tag == '45:41:66:9a:7e:aa:ee:61:e7:08:dc:7c:bc:c5:eb:62'
    print("Test Vector #4 ok")


def testVector5():
    """
        Test Vector #5: If one uses 130-bit partial reduction, does the code
        handle the case where partially reduced final result is not fully
        reduced?
    """
    R = b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    S = b'\x00' * 16
    key = R + S
    data = b'\xff' * 16
    tag = Poly1305.poly1305_mac(data, key)
    assert tag == "03:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    print("Test Vector #5 ok")


def testVector6():
    """
        Test Vector #6: What happens if addition of s overflows modulo 2^128?
    """
    R = b'\x02' + b'\x00' * 15
    S = b'\xff' * 16
    key = R + S
    data = b'\x02' + b'\x00' * 15
    tag = Poly1305.poly1305_mac(data, key)
    assert tag == "03:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    print("Test Vector #6 ok")


def testVector7():
    """
        Test Vector #7: What happens if data limb is all ones and there is
        carry from lower limb?
    """
    R = b'\x01' + b'\x00' * 15
    S = b'\x00' * 16
    key = R + S
    data = b'\xff' * 16 + b'\xf0' + b'\xff' * 15 + b'\x11' + b'\x00' * 15
    tag = Poly1305.poly1305_mac(data, key)
    assert tag == "05:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    print("Test Vector #7 ok")


def testVector8():
    """
        Test Vector #8: What happens if final result from polynomial part is
        exactly 2^130-5?
    """
    R = b'\x01' + b'\x00' * 15
    S = b'\x00' * 16
    key = R + S
    data = b'\xff' * 16 + b'\xfb' + b'\xfe' * 15 + b'\x01' * 16
    tag = Poly1305.poly1305_mac(data, key)

    assert tag == "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    print("Test Vector #8 ok")


def testVector9():
    """
        Test Vector #9: What happens if final result from polynomial part is
        exactly 2^130-6?
    """
    R = b'\x02' + b'\x00' * 15
    S = b'\x00' * 16
    key = R + S

    data = b'\xfd' + b'\xff' * 15
    tag = Poly1305.poly1305_mac(data, key)
    assert tag == 'FA:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF'.lower()
    print("Test Vector #9 ok")


def testVector10():
    """
        Test Vector #10: What happens if 5*H+L-type reduction produces
        131-bit intermediate result?
    """
    R = b'\x01' + b'\x00' * 7 + b'\x04' + b'\x00' * 7
    S = b'\x00' * 16
    key = R + S

    data = b'\xE3\x35\x94\xD7\x50\x5E\x43\xB9\x00\x00\x00\x00\x00\x00\x00\x00\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    tag = Poly1305.poly1305_mac(data, key)
    assert tag == "14:00:00:00:00:00:00:00:55:00:00:00:00:00:00:00"
    print("Test Vector #10 ok")


def testVector11():
    """
        Test Vector #11: What happens if 5*H+L-type reduction produces
        131-bit final result?
    """
    R = b'\x01' + b'\x00' * 7 + b'\x04' + b'\x00' * 7
    S = b'\x00' * 16
    key = R + S
    data = b'\xE3\x35\x94\xD7\x50\x5E\x43\xB9\x00\x00\x00\x00\x00\x00\x00\x00\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    tag = Poly1305.poly1305_mac(data, key)
    assert tag == "13:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    print("Test Vector #11 ok")


def all_tests():
    testPoly1305()
    testVector4()
    testVector5()
    testVector6()
    testVector7()
    testVector8()
    testVector9()
    testVector10()
    testVector11()


if __name__ == "__main__":
    all_tests()
