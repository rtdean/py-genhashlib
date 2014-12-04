import types


MAX_INT = 0xffffffff
BITS_IN_INT = 8 * 4


def elf(key):
    """
    The published hash algorithm used in the UNIX ELF format for object
    files.  Accepts a string to be hashed and returns an integer
    :param key:
    :return:
    """
    assert isinstance(key, types.StringTypes), 'key: must be a string'
    result = 0
    for c in key:
        result = ((result & 0x0fffffff) << 4) + ord(c)
        x = result & 0xf0000000
        if x != 0:
            result ^= x >> 24
        result &= ~x
    return result


def pjw(key):
    """
    An adaptation of Peter Weinberger's (PJW) generic hashing algorithm based on
    Allen Holub's version.  Accepts a string to be hashed and returns an integer

    :param key:
    :return:
    """
    assert isinstance(key, types.StringTypes), 'key: must be a string'
    three_quarters = long((BITS_IN_INT * 3) / 4)
    one_eighth = long(BITS_IN_INT / 8)
    high_bits = (MAX_INT << (BITS_IN_INT - one_eighth)) & MAX_INT
    hash_value = 0
    for char in key:
        hash_value = ( hash_value << one_eighth) + ord(char)
        i = hash_value & 0xF0000000
        if i != 0:
            hash_value = ( hash_value ^ (i >> three_quarters)) & ~high_bits
    return hash_value & 0x7fffffff
