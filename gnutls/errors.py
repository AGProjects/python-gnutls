# Copyright (C) 2007 AG Projects
#

"""GNUTLS errors"""

__all__ = ['Error', 'GNUTLSError', 'OperationWouldBlock', 'OperationInterrupted',
           'CertificateError', 'X509NameError', 'GNUTLSException']

from gnutls.library.constants import GNUTLS_E_AGAIN, GNUTLS_E_INTERRUPTED, GNUTLS_E_NO_CERTIFICATE_FOUND
from gnutls.library.constants import GNUTLS_E_MEMORY_ERROR, GNUTLS_E_SHORT_MEMORY_BUFFER
from gnutls.library.functions import gnutls_strerror

class Error(Exception): pass

class GNUTLSError(Error): pass
class OperationWouldBlock(GNUTLSError): pass
class OperationInterrupted(GNUTLSError): pass

class CertificateError(Error): pass
class X509NameError(Error): pass


class ErrorMessage(str):
    def __new__(cls, code):
        obj = str.__new__(cls, gnutls_strerror(code))
        obj.code = code
        return obj


class GNUTLSException(object):
    @classmethod
    def check(cls, retcode):
        if retcode >= 0:
            return
        elif retcode == GNUTLS_E_AGAIN:
            raise OperationWouldBlock(gnutls_strerror(retcode))
        elif retcode == GNUTLS_E_INTERRUPTED:
            raise OperationInterrupted(gnutls_strerror(retcode))
        elif retcode in (GNUTLS_E_MEMORY_ERROR, GNUTLS_E_SHORT_MEMORY_BUFFER):
            raise MemoryError(gnutls_strerror(retcode))
        elif retcode in (GNUTLS_E_NO_CERTIFICATE_FOUND, ):
            raise CertificateError(gnutls_strerror(retcode))
        else:
            raise GNUTLSError(ErrorMessage(retcode))

