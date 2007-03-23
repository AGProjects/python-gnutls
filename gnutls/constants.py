# Copyright (C) 2007 AG Projects
#

"""GNUTLS constants"""

__all__ = [
    ## Certificate formats
    'X509_FMT_DER', 'X509_FMT_PEM',

    ## Certificate verification status
    'CERT_INVALID', 'CERT_REVOKED', 'CERT_SIGNER_NOT_FOUND', 'CERT_SIGNER_NOT_CA', 'CERT_INSECURE_ALGORITHM'
]

from gnutls.library import constants

class GNUTLSConstant(int):
    def __new__(cls, name, value):
        instance = int.__new__(cls, value)
        instance.name = name
        return instance
    def __repr__(self):
        return self.name

## Generate all exported constants
code = '\n'.join(["%s = GNUTLSConstant('%s', constants.GNUTLS_%s)" % (name, name, name) for name in __all__])
exec code in locals(), globals()
del code

