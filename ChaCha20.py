import utils


def ChaCha20Encrypt(key, counter, nonce, plaintext):
    cipher = b''
    for j in range(len(plaintext) // 64):
        keyStream = ChaCha20Block(key, counter+j, nonce)
        block = plaintext[j*64:(j+1)*64]
        cipher += utils.byte_xor(block, keyStream)
    if ((len(plaintext) % 64) != 0):
        j = len(plaintext) // 64
        keyStream = ChaCha20Block(key, counter+j, nonce)
        block = plaintext[j*64:]
        cipher += utils.byte_xor(block,
                                 keyStream)[:(len(plaintext) % 64)+1]

    return cipher


def ChaCha20Block(key, counter, nonce):
    state = [0x61707865, 0x3320646e,
             0x79622d32, 0x6b206574]
    state += key
    state += [counter]
    state += nonce
    initialState = state.copy()
    for i in range(10):
        Round(state)
    state = [(b[0] + b[1]) & 0xFFFFFFFF for b in zip(state, initialState)]
    return serialize(state)


def QuarterRoundAux(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = utils.left_rotate(d, 16)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = utils.left_rotate(b, 12)
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = utils.left_rotate(d, 8)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = utils.left_rotate(b, 7)
    return (a, b, c, d)


def QuarterRound(state, x, y, z, w):
    a = state[x]
    b = state[y]
    c = state[z]
    d = state[w]
    (a, b, c, d) = QuarterRoundAux(a, b, c, d)
    state[x] = a
    state[y] = b
    state[z] = c
    state[w] = d


def Round(state):
    # column round
    QuarterRound(state, 0, 4, 8, 12)
    QuarterRound(state, 1, 5, 9, 13)
    QuarterRound(state, 2, 6, 10, 14)
    QuarterRound(state, 3, 7, 11, 15)
    # diagonal round
    QuarterRound(state, 0, 5, 10, 15)
    QuarterRound(state, 1, 6, 11, 12)
    QuarterRound(state, 2, 7, 8, 13)
    QuarterRound(state, 3, 4, 9, 14)


def serialize(state):
    """
        Used to serialize a state into bytes
    """
    serializedBlock = b''
    for i in state:
        serializedBlock += i.to_bytes(4, "little")
    return serializedBlock
