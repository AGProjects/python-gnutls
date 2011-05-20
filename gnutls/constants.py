# Copyright (C) 2007 AG Projects. See LICENSE for details.
#

"""GNUTLS constants"""

__all__ = [
    ## GNUTLS session protocols
    'PROTO_TLS1_2', 'PROTO_TLS1_1', 'PROTO_TLS1_0', 'PROTO_SSL3',
    
    ## Key exchange algorithms
    'KX_RSA', 'KX_DHE_DSS', 'KX_DHE_RSA', 'KX_RSA_EXPORT', 'KX_ANON_DH',
    
    ## Ciphers
    'CIPHER_AES_128_CBC', 'CIPHER_3DES_CBC', 'CIPHER_ARCFOUR_128', 'CIPHER_AES_256_CBC', 'CIPHER_DES_CBC', 'CIPHER_CAMELLIA_256_CBC', 'CIPHER_CAMELLIA_128_CBC',
    
    ## MAC algorithms
    'MAC_SHA512', 'MAC_SHA384', 'MAC_SHA256', 'MAC_SHA1', 'MAC_MD5', 'MAC_RMD160',
    
    ## Compressions
    'COMP_DEFLATE', 'COMP_LZO', 'COMP_NULL',

    ## Credential types
    'CRED_CERTIFICATE', 'CRED_ANON',

    ## X509 certificate/private key formats
    'X509_FMT_DER', 'X509_FMT_PEM',

    ## Miscellaneous
    'CERT_REQUEST', 'CERT_REQUIRE', 'SHUT_RDWR', 'SHUT_WR'
]

__name_map__ = {
    'PROTO_TLS1_2': 'TLS1_2', 'PROTO_TLS1_1': 'TLS1_1', 'PROTO_TLS1_0': 'TLS1_0',
    'PROTO_SSL3': 'SSL3', 'CRED_CERTIFICATE': 'CRD_CERTIFICATE', 'CRED_ANON': 'CRD_ANON'
}


from gnutls.library import constants

class GNUTLSConstant(int):
    def __new__(cls, name):
        gnutls_name = 'GNUTLS_' + __name_map__.get(name, name)
        instance = int.__new__(cls, getattr(constants, gnutls_name))
        instance.name = name
        return instance
    def __repr__(self):
        return self.name

## Generate all exported constants
code = '\n'.join(["%s = GNUTLSConstant('%s')" % (name, name) for name in __all__])
exec code in locals(), globals()
del code, name

del constants
