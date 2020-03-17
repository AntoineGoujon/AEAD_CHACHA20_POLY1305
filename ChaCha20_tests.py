#!/usr/bin/env python3

from ChaCha20 import *
import utils


def testChaChaQuarterRoundAux():
    a = 0x11111111
    b = 0x01020304
    c = 0x9b8d6f43
    d = 0x01234567
    (a, b, c, d) = QuarterRoundAux(a, b, c, d)
    assert a == 0xea2a92f4
    assert b == 0xcb1cf8ce
    assert c == 0x4581472e
    assert d == 0x5881c4bb
    print('ChaChaQuarterRoundAux ok')


def testChaChaQuarterRound():

    state = [0x879531e0,  0xc5ecf37d,  0x516461b1,  0xc9a62f8a,
             0x44c20ef3,  0x3390af7f,  0xd9fc690b,  0x2a5f714c,
             0x53372767,  0xb00a5631,  0x974c541a,  0x359e9963,
             0x5c971061,  0x3d631689,  0x2098d9d6,  0x91dbd320]

    expectedState = [0x879531e0,  0xc5ecf37d,  0xbdb886dc,  0xc9a62f8a,
                     0x44c20ef3,  0x3390af7f,  0xd9fc690b,  0xcfacafd2,
                     0xe46bea80,  0xb00a5631,  0x974c541a,  0x359e9963,
                     0x5c971061,  0xccc07c79,  0x2098d9d6,  0x91dbd320]

    QuarterRound(state, 2, 7, 8, 13)

    assert state == expectedState
    print('ChaChaQuarterRound ok')


def testBlockFunction():
    key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
    nonce = "00:00:00:09:00:00:00:4a:00:00:00:00"
    blockCount = 1
    k = utils.unpack(key)
    n = utils.unpack(nonce)

    expectedState = [0xe4e7f110,  0x15593bd1,  0x1fdd0f50,  0xc47120a3,
                     0xc7f4d1c7,  0x0368c033,  0x9aaa2204,  0x4e6cd4c3,
                     0x466482d2,  0x09aa9f07,  0x05d7c214,  0xa2028bd9,
                     0xd19c12b5,  0xb94e16de,  0xe883d0cb,  0x4e3c50a2]
    state = ChaCha20Block(k, blockCount, n)
    assert state == serialize(expectedState)
    print('ChaChaBlock ok')


def testEncrypt():
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
    nonce = "00:00:00:00:00:00:00:4a:00:00:00:00"
    counter = 1

    k = utils.unpack(key)
    n = utils.unpack(nonce)

    c = ChaCha20Encrypt(k, counter, n, plaintext.encode())

    plain = ChaCha20Encrypt(k, counter, n, c)
    assert plain == plaintext.encode()
    print("ChaCha20 encryption ok")


def testEncrypt2():
    k = [0] * 32
    n = [0] * 11
    counter = 0
    plaintext = b'\x00' * 64

    c = ChaCha20Encrypt(k, counter, n, plaintext)
    expected_cipher = b'\x76\xb8\xe0\xad\xa0\xf1\x3d\x90\x40\x5d\x6a\xe5\x53\x86\xbd\x28\xbd\xd2\x19\xb8\xa0\x8d\xed\x1a\xa8\x36\xef\xcc\x8b\x77\x0d\xc7\xda\x41\x59\x7c\x51\x57\x48\x8d\x77\x24\xe0\x3f\xb8\xd8\x4a\x37\x6a\x43\xb8\xf4\x15\x18\xa1\x1c\xc3\x87\xb6\x69\xb2\xee\x65\x86'
    assert c == expected_cipher
    print("Test Vector #1 ok")


def testEncrypt3():
    key = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01".replace(
        " ", ":")
    nonce = "00 00 00 00 00 00 00 00 00 00 00 02".replace(" ", ":")
    k = utils.unpack(key)
    n = utils.unpack(nonce)
    counter = 1

    plaintext = """Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to""".encode()

    expected_cipher = b'\xa3\xfb\xf0\x7d\xf3\xfa\x2f\xde\x4f\x37\x6c\xa2\x3e\x82\x73\x70\x41\x60\x5d\x9f\x4f\x4f\x57\xbd\x8c\xff\x2c\x1d\x4b\x79\x55\xec\x2a\x97\x94\x8b\xd3\x72\x29\x15\xc8\xf3\xd3\x37\xf7\xd3\x70\x05\x0e\x9e\x96\xd6\x47\xb7\xc3\x9f\x56\xe0\x31\xca\x5e\xb6\x25\x0d\x40\x42\xe0\x27\x85\xec\xec\xfa\x4b\x4b\xb5\xe8\xea\xd0\x44\x0e\x20\xb6\xe8\xdb\x09\xd8\x81\xa7\xc6\x13\x2f\x42\x0e\x52\x79\x50\x42\xbd\xfa\x77\x73\xd8\xa9\x05\x14\x47\xb3\x29\x1c\xe1\x41\x1c\x68\x04\x65\x55\x2a\xa6\xc4\x05\xb7\x76\x4d\x5e\x87\xbe\xa8\x5a\xd0\x0f\x84\x49\xed\x8f\x72\xd0\xd6\x62\xab\x05\x26\x91\xca\x66\x42\x4b\xc8\x6d\x2d\xf8\x0e\xa4\x1f\x43\xab\xf9\x37\xd3\x25\x9d\xc4\xb2\xd0\xdf\xb4\x8a\x6c\x91\x39\xdd\xd7\xf7\x69\x66\xe9\x28\xe6\x35\x55\x3b\xa7\x6c\x5c\x87\x9d\x7b\x35\xd4\x9e\xb2\xe6\x2b\x08\x71\xcd\xac\x63\x89\x39\xe2\x5e\x8a\x1e\x0e\xf9\xd5\x28\x0f\xa8\xca\x32\x8b\x35\x1c\x3c\x76\x59\x89\xcb\xcf\x3d\xaa\x8b\x6c\xcc\x3a\xaf\x9f\x39\x79\xc9\x2b\x37\x20\xfc\x88\xdc\x95\xed\x84\xa1\xbe\x05\x9c\x64\x99\xb9\xfd\xa2\x36\xe7\xe8\x18\xb0\x4b\x0b\xc3\x9c\x1e\x87\x6b\x19\x3b\xfe\x55\x69\x75\x3f\x88\x12\x8c\xc0\x8a\xaa\x9b\x63\xd1\xa1\x6f\x80\xef\x25\x54\xd7\x18\x9c\x41\x1f\x58\x69\xca\x52\xc5\xb8\x3f\xa3\x6f\xf2\x16\xb9\xc1\xd3\x00\x62\xbe\xbc\xfd\x2d\xc5\xbc\xe0\x91\x19\x34\xfd\xa7\x9a\x86\xf6\xe6\x98\xce\xd7\x59\xc3\xff\x9b\x64\x77\x33\x8f\x3d\xa4\xf9\xcd\x85\x14\xea\x99\x82\xcc\xaf\xb3\x41\xb2\x38\x4d\xd9\x02\xf3\xd1\xab\x7a\xc6\x1d\xd2\x9c\x6f\x21\xba\x5b\x86\x2f\x37\x30\xe3\x7c\xfd\xc4\xfd\x80\x6c\x22\xf2\x21'
    c = ChaCha20Encrypt(k, counter, n, plaintext)
    assert c == expected_cipher
    print("Test Vector #2 ok")


def all_tests():
    testChaChaQuarterRoundAux()
    testChaChaQuarterRound()
    testBlockFunction()
    testEncrypt()
    testEncrypt2()
    testEncrypt3()


if __name__ == "__main__":
    all_tests()
