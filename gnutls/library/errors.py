# Copyright (C) 2007 AG Projects. See LICENSE for details.
#

"""GNUTLS library errors"""

from gnutls.errors import *
from gnutls.errors import __all__

from gnutls.library.constants import GNUTLS_E_AGAIN, GNUTLS_E_INTERRUPTED, GNUTLS_E_NO_CERTIFICATE_FOUND
from gnutls.library.constants import GNUTLS_E_MEMORY_ERROR, GNUTLS_E_SHORT_MEMORY_BUFFER
from gnutls.library.constants import GNUTLS_E_FATAL_ALERT_RECEIVED, GNUTLS_A_BAD_CERTIFICATE
from gnutls.library.constants import GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
from gnutls.library.constants import GNUTLS_A_UNKNOWN_CA, GNUTLS_A_INSUFFICIENT_SECURITY
from gnutls.library.constants import GNUTLS_A_CERTIFICATE_EXPIRED, GNUTLS_A_CERTIFICATE_REVOKED
from gnutls.library.functions import gnutls_strerror, gnutls_alert_get

class ErrorMessage(str):
    def __new__(cls, code):
        obj = str.__new__(cls, gnutls_strerror(code))
        obj.code = code
        return obj

# Check functions which return an integer status code (negative codes being errors)
#
class ErrorHandler(object):
    alert_map = {
        GNUTLS_A_BAD_CERTIFICATE       : CertificateError("peer rejected our certificate as invalid"),
        GNUTLS_A_UNKNOWN_CA            : CertificateAuthorityError("peer does not trust our certificate authority"),
        GNUTLS_A_INSUFFICIENT_SECURITY : CertificateSecurityError("peer rejected us on insufficient security"),
        GNUTLS_A_CERTIFICATE_EXPIRED   : CertificateExpiredError("peer rejected our certificate as expired"),
        GNUTLS_A_CERTIFICATE_REVOKED   : CertificateRevokedError("peer rejected our certificate as revoked")
    }

    function_map = dict(
        gnutls_certificate_activation_time_peers          = "cannot get certificate activation time",
        gnutls_certificate_expiration_time_peers          = "cannot get certificate expiration time",
        gnutls_x509_crl_get_next_update                   = "cannot get CRL's next update time",
        gnutls_x509_crl_get_this_update                   = "cannot get CRL's issue time",
        gnutls_x509_crt_get_activation_time               = "cannot get X509 certificate activation time",
        gnutls_x509_crt_get_expiration_time               = "cannot get X509 certificate expiration time",
        gnutls_openpgp_crt_get_creation_time              = "cannot get OpenPGP key creation time",
        gnutls_openpgp_crt_get_expiration_time            = "cannot get OpenPGP key expiration time",
        gnutls_openpgp_crt_get_subkey_creation_time       = "cannot get OpenPGP subkey creation time",
        gnutls_openpgp_crt_get_subkey_expiration_time     = "cannot get OpenPGP subkey expiration time",
        gnutls_openpgp_privkey_get_subkey_creation_time   = "cannot get OpenPGP subkey creation time",
        gnutls_openpgp_privkey_get_subkey_expiration_time = "cannot get OpenPGP subkey expiration time"
    )

    @classmethod
    def check_status(cls, retcode, function, args):
        if retcode >= 0:
            return retcode
        elif retcode == -1:
            raise GNUTLSError(cls.function_map.get(function.__name__) or ErrorMessage(retcode))
        elif retcode == GNUTLS_E_AGAIN:
            raise OperationWouldBlock(gnutls_strerror(retcode))
        elif retcode == GNUTLS_E_INTERRUPTED:
            raise OperationInterrupted(gnutls_strerror(retcode))
        elif retcode in (GNUTLS_E_MEMORY_ERROR, GNUTLS_E_SHORT_MEMORY_BUFFER):
            raise MemoryError(ErrorMessage(retcode))
        elif retcode == GNUTLS_E_NO_CERTIFICATE_FOUND:
            raise CertificateSecurityError(gnutls_strerror(retcode))
        elif retcode == GNUTLS_E_FATAL_ALERT_RECEIVED:
            exception = cls.alert_map.get(gnutls_alert_get(args[0]))
            raise exception and exception.__class__(*exception.args) or GNUTLSError(ErrorMessage(retcode))
        elif retcode == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE:
            raise RequestedDataNotAvailable(gnutls_strerror(retcode))
        else:
            raise GNUTLSError(ErrorMessage(retcode))


# Attach the error checking function to all functions returning integers
#
from gnutls.library import functions
from ctypes import c_int, c_long

if not set(functions.__all__).issuperset(ErrorHandler.function_map):
    raise RuntimeError("ErrorHandler.function_map is not synchronized with the function names anymore")

for func in (obj for name, obj in functions.__dict__.iteritems() if name in functions.__all__ and obj.restype in (c_int, c_long)):
    func.errcheck = ErrorHandler.check_status

del c_int, c_long, func, functions

