# Copyright (C) 2007 AG Projects
#

"""GNUTLS library errors"""

from gnutls.errors import *
from gnutls.errors import __all__

from gnutls.library.constants import GNUTLS_E_AGAIN, GNUTLS_E_INTERRUPTED, GNUTLS_E_NO_CERTIFICATE_FOUND
from gnutls.library.constants import GNUTLS_E_MEMORY_ERROR, GNUTLS_E_SHORT_MEMORY_BUFFER
from gnutls.library.functions import gnutls_strerror

class ErrorMessage(str):
    def __new__(cls, code):
        obj = str.__new__(cls, gnutls_strerror(code))
        obj.code = code
        return obj

# Check functions which return an integer status code (negative codes being errors)
#
def _check_status(retcode, function, args):
    if retcode >= 0:
        return retcode
    elif retcode == -1:
        from gnutls.library import functions
        if function in (functions.gnutls_certificate_activation_time_peers,
                        functions.gnutls_x509_crt_get_activation_time,
                        functions.gnutls_openpgp_key_get_creation_time):
            raise GNUTLSError("cannot retrieve activation time")
        elif function in (functions.gnutls_certificate_expiration_time_peers,
                          functions.gnutls_x509_crt_get_expiration_time,
                          functions.gnutls_openpgp_key_get_expiration_time):
            raise GNUTLSError("cannot retrieve expiration time")
        elif function in (functions.gnutls_x509_crl_get_this_update,
                          functions.gnutls_x509_crl_get_next_update):
            raise GNUTLSError("cannot retrieve CRL update time")
        else:
            raise GNUTLSError(ErrorMessage(retcode))
    elif retcode == GNUTLS_E_AGAIN:
        raise OperationWouldBlock(gnutls_strerror(retcode))
    elif retcode == GNUTLS_E_INTERRUPTED:
        raise OperationInterrupted(gnutls_strerror(retcode))
    elif retcode in (GNUTLS_E_MEMORY_ERROR, GNUTLS_E_SHORT_MEMORY_BUFFER):
        raise MemoryError(ErrorMessage(retcode))
    elif retcode in (GNUTLS_E_NO_CERTIFICATE_FOUND, ):
        raise CertificateError(gnutls_strerror(retcode))
    else:
        raise GNUTLSError(ErrorMessage(retcode))

# Attach the error checking function to all functions returning integers
#
from gnutls.library import functions
from ctypes import c_int, c_long

for func in functions.__dict__.values():
    if not hasattr(func, 'errcheck'):
        continue ## not a function
    if func.restype in (c_int, c_long):
        func.errcheck = _check_status

del c_int, c_long, func, functions

