def left_rotate(n, d):
    '''n-bit left roll'''
    return ((n << d) | (n >> (32 - d))) & 0xFFFFFFFF


def byte_xor(b1, b2):
    return bytes([a ^ b for a, b in zip(b1, b2)])


def unpack(s):
    """
        Transform an string input of format:
        byte:byte:byte...
        into an array of ints
    """
    t = s.split(':')
    assert len(t) % 4 == 0
    d = []
    for i in range(len(t)//4):
        q = t[4*i:4*(i+1)]
        q.reverse()
        d += [int(''.join(q), 16)]
    return d
