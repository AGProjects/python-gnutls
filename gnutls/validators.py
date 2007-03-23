# Copyright (C) 2007 AG Projects
#

"""GNUTLS validators"""

__all__ = ['ProtocolValidator', 'KeyExchangeValidator', 'CipherValidator', 'MACValidator', 'CompressionValidator']

from gnutls.constants import *

class ProtocolValidator(tuple):
    _protocols = set((PROTO_TLS1_1, PROTO_TLS1_0, PROTO_SSL3))

    def __new__(cls, arg):
        if not isinstance(arg, (tuple, list)):
            raise TypeError("Argument must be a tuple or list")
        if not arg:
            raise ValueError("Protocol list cannot be empty")
        if not cls._protocols.issuperset(set(arg)):
            raise ValueError("Got invalid protocol")
        return tuple.__new__(cls, arg)


class KeyExchangeValidator(tuple):
    _algorithms = set((KX_RSA, KX_DHE_DSS, KX_DHE_RSA, KX_RSA_EXPORT, KX_ANON_DH))

    def __new__(cls, arg):
        if not isinstance(arg, (tuple, list)):
            raise TypeError("Argument must be a tuple or list")
        if not arg:
            raise ValueError("Key exchange algorithm list cannot be empty")
        if not cls._algorithms.issuperset(set(arg)):
            raise ValueError("Got invalid key exchange algorithm")
        return tuple.__new__(cls, arg)


class CipherValidator(tuple):
    _ciphers = set((CIPHER_AES_128_CBC, CIPHER_3DES_CBC, CIPHER_ARCFOUR_128, CIPHER_AES_256_CBC, CIPHER_DES_CBC))

    def __new__(cls, arg):
        if not isinstance(arg, (tuple, list)):
            raise TypeError("Argument must be a tuple or list")
        if not arg:
            raise ValueError("Cipher list cannot be empty")
        if not cls._ciphers.issuperset(set(arg)):
            raise ValueError("Got invalid cipher")
        return tuple.__new__(cls, arg)


class MACValidator(tuple):
    _algorithms = set((MAC_SHA1, MAC_MD5, MAC_RMD160))

    def __new__(cls, arg):
        if not isinstance(arg, (tuple, list)):
            raise TypeError("Argument must be a tuple or list")
        if not arg:
            raise ValueError("MAC algorithm list cannot be empty")
        if not cls._algorithms.issuperset(set(arg)):
            raise ValueError("Got invalid MAC algorithm")
        return tuple.__new__(cls, arg)


class CompressionValidator(tuple):
    _compressions = set((COMP_DEFLATE, COMP_LZO, COMP_NULL))

    def __new__(cls, arg):
        if not isinstance(arg, (tuple, list)):
            raise TypeError("Argument must be a tuple or list")
        if not arg:
            raise ValueError("Compression list cannot be empty")
        if not cls._compressions.issuperset(set(arg)):
            raise ValueError("Got invalid compression")
        return tuple.__new__(cls, arg)

