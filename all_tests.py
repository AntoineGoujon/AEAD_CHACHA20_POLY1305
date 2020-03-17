#!/usr/bin/env python3

import ChaCha20_tests
import Poly1305_tests
import AEAD_tests


def all_tests():
    ChaCha20_tests.all_tests()
    Poly1305_tests.all_tests()
    AEAD_tests.all_tests()


if __name__ == "__main__":
    all_tests()
