# Copyright (C) 2007 AG Projects
#

"""GNUTLS constants"""

__all__ = [
    ## Certificate formats
    'X509_FMT_DER', 'X509_FMT_PEM',

    ## Certificate verification status
    'CERT_INVALID', 'CERT_REVOKED', 'CERT_SIGNER_NOT_FOUND', 'CERT_SIGNER_NOT_CA', 'CERT_INSECURE_ALGORITHM',
    
    ## GNUTLS session protocols
    'PROTO_TLS1_1', 'PROTO_TLS1_0', 'PROTO_SSL3'
]

__name_map__ = {'PROTO_TLS1_1': 'TLS1_1', 'PROTO_TLS1_0': 'TLS1_0', 'PROTO_SSL3': 'SSL3'}


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
