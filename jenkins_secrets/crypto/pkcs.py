"""Cryptographic functions for PKCS5 padding
"""


def pkcs5_unpad(data):
    """Removes PKCS#5 padding from data.

    """
    count = ord(data[-1])
    assert data[-count:] == data[-1]*count
    return data[:-count]
