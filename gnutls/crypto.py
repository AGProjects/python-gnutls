# Copyright (C) 2007 AG Projects
#

"""GNUTLS crypo support"""

# TODO: better error handling and check the error hierarchy

__all__ = ['X509_FMT_DER', 'X509_FMT_PEM', 'X509Cert', 'X509CRL', 'PrivateKey']

import re
from ctypes import *

from gnutls import *
from gnutls.library.constants import *
from gnutls.library.types import *
from gnutls.library.functions import *

# Certificate format
X509_FMT_DER = GNUTLS_X509_FMT_DER
X509_FMT_PEM = GNUTLS_X509_FMT_PEM

# enum gnutls_certificate_status_t; used in the verify process
CERT_INVALID            = GNUTLS_CERT_INVALID
CERT_REVOKED            = GNUTLS_CERT_REVOKED
CERT_SIGNER_NOT_FOUND   = GNUTLS_CERT_SIGNER_NOT_FOUND
CERT_SIGNER_NOT_CA      = GNUTLS_CERT_SIGNER_NOT_CA
CERT_INSECURE_ALGORITHM = GNUTLS_CERT_INSECURE_ALGORITHM

class X509NameError(Error): pass


class X509NameMeta(type):
    long_names = {'country': 'C',
                  'state': 'ST',
                  'locatity': 'L',
                  'common_name': 'CN',
                  'organization': 'O',
                  'organization_unit': 'OU',
                  'email': 'EMAIL'}
    def __new__(cls, name, bases, dic):
        instance = type.__new__(cls, name, bases, dic)
        instance.ids = X509NameMeta.long_names.values()
        for long_name, short_name in X509NameMeta.long_names.items():
            ## Map a long_name property to the short_name attribute
            cls.add_property(instance, long_name, short_name)
        return instance
    def add_property(instance, name, short_name):
        setattr(instance, name, property(lambda self: getattr(self, short_name, None)))


class X509Name(str):
    __metaclass__ = X509NameMeta

    def __init__(self, dname):
        str.__init__(self, dname)
        pairs = [x.replace('\,', ',') for x in re.split(r'(?<!\\),\s*', dname)]
        for pair in pairs:
            try:
                name, value = pair.split('=')
            except ValueError:
                raise X509NameError("Invalid X509 distinguished name: %s" % dname)
            str.__setattr__(self, name, value)
        for name in X509Name.ids:
            if not hasattr(self, name):
                str.__setattr__(self, name, None)
    def __setattr__(self, name, value):
        if name in X509Name.ids:
            raise AttributeError("can't set attribute")
        str.__setattr__(self, name, value)


class X509Cert(object):
    def __init__(self, buffer, format=X509_FMT_PEM):
        self.__deinit = gnutls_x509_crt_deinit
        self._cert = gnutls_x509_crt_t()
        if format not in (X509_FMT_PEM, X509_FMT_DER):
            raise ValueError("Incorrect format: " + format)
        # int gnutls_x509_crt_init (gnutls_x509_crt_t * cert)
        retcode = gnutls_x509_crt_init(byref(self._cert))
        GNUTLSException.check(retcode)
        data = gnutls_datum_t(cast(c_char_p(buffer), POINTER(c_ubyte)), c_uint(len(buffer)))
        # int gnutls_x509_crt_import (gnutls_x509_crt_t cert, const gnutls_datum_t * data, gnutls_x509_crt_fmt_t format
        retcode = gnutls_x509_crt_import(self._cert, byref(data), format)
        GNUTLSException.check(retcode)

    @property
    def subject(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        # int gnutls_x509_crt_get_dn (gnutls_x509_crt_t cert, char * buf, size_t * sizeof_buf)
        retcode = gnutls_x509_crt_get_dn(self._cert, dname, byref(size))
        if retcode == GNUTLS_E_SHORT_MEMORY_BUFFER:
            dname = create_string_buffer(size.value)
            retcode = gnutls_x509_crt_get_dn(self._cert, dname, byref(size))
        GNUTLSException.check(retcode)
        return X509Name(dname.value)

    @property
    def issuer(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        # int gnutls_x509_crt_get_issuer_dn (gnutls_x509_crt_t cert, char * buf, size_t * sizeof_buf)
        retcode = gnutls_x509_crt_get_issuer_dn(self._cert, dname, byref(size))
        if retcode == GNUTLS_E_SHORT_MEMORY_BUFFER:
            dname = create_string_buffer(size.value)
            retcode = gnutls_x509_crt_get_issuer_dn(self._cert, dname, byref(size))
        GNUTLSException.check(retcode)
        return X509Name(dname.value)

    @property
    def serial_number(self):
        size = c_size_t(1)
        serial = c_ulong()
        # int gnutls_x509_crt_get_serial (gnutls_x509_crt_t cert, void * result, size_t * result_size)
        retcode = gnutls_x509_crt_get_serial(self._cert, cast(byref(serial), c_void_p), byref(size))
        if retcode == GNUTLS_E_SHORT_MEMORY_BUFFER:
            import struct, sys
            serial = create_string_buffer(size.value * sizeof(c_void_p))
            retcode = gnutls_x509_crt_get_serial(self._cert, cast(serial, c_void_p), byref(size))
            GNUTLSException.check(retcode)
            pad = size.value * sizeof(c_void_p) - len(serial.value)
            format = '@%dL' % size.value
            numbers = list(struct.unpack(format, serial.value + pad*'\x00'))
            if sys.byteorder == 'little':
                numbers.reverse()
            number = 0
            offset = sizeof(c_void_p) * 8
            for n in numbers:
                number = (number<<offset) + n
            return number
        else:
            GNUTLSException.check(retcode)
            return serial.value

    @property
    def activation_time(self):
        # time_t gnutls_x509_crt_get_activation_time (gnutls_x509_crt_t cert)
        retcode = gnutls_x509_crt_get_activation_time(self._cert)
        if retcode == -1:
            raise GNUTLSError("cannot retrieve activation time")
        GNUTLSException.check(retcode)
        return retcode

    @property
    def expiration_time(self):
        # time_t gnutls_x509_crt_get_expiration_time (gnutls_x509_crt_t cert)
        retcode = gnutls_x509_crt_get_expiration_time(self._cert)
        if retcode == -1:
            raise GNUTLSError("cannot not retrieve expiration time")
        GNUTLSException.check(retcode)
        return retcode

    @property
    def version(self):
        # int gnutls_x509_crt_get_version (gnutls_x509_crt_t cert)
        retcode = gnutls_x509_crt_get_version(self._cert)
        GNUTLSException.check(retcode)
        return retcode

    def check_issuer(self, issuer):
        '''Return True if the certificate was issued by the given issuer, False otherwise.'''
        if not isinstance(issuer, X509Cert):
            raise TypeError("issuer must be a X509Cert object")
        # int gnutls_x509_crt_check_issuer (gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer)
        retcode = gnutls_x509_crt_check_issuer(self._cert, issuer._cert)
        GNUTLSException.check(retcode)
        return bool(retcode)

    def __del__(self):
        self.__deinit(self._cert)


class PrivateKey(object):
    def __init__(self, buffer, format=X509_FMT_PEM):
        self.__deinit = gnutls_x509_privkey_deinit
        self._key = gnutls_x509_privkey_t()
        if format not in (X509_FMT_PEM, X509_FMT_DER):
            raise ValueError("Incorrect format: " + format)
        # int gnutls_x509_privkey_init (gnutls_x509_privkey_t * key)
        retcode = gnutls_x509_privkey_init(byref(self._key))
        GNUTLSException.check(retcode)
        data = gnutls_datum_t(cast(c_char_p(buffer), POINTER(c_ubyte)), c_uint(len(buffer)))
        # int gnutls_x509_privkey_import (gnutls_x509_privkey_t key, const gnutls_datum_t * data, gnutls_x509_crt_fmt_t format)        
        retcode = gnutls_x509_privkey_import(self._key, byref(data), format)
        GNUTLSException.check(retcode)

    def __del__(self):
        self.__deinit(self._key)


class X509CRL(object):
    def __init__(self, buffer, format=X509_FMT_PEM):
        self.__deinit = gnutls_x509_crl_deinit
        self._crl = gnutls_x509_crl_t()
        if format not in (X509_FMT_PEM, X509_FMT_DER):
            raise ValueError("Incorrect format: " + format)
        # int gnutls_x509_crl_init (gnutls_x509_crl_t * crl)
        retcode = gnutls_x509_crl_init(byref(self._crl))
        GNUTLSException.check(retcode)
        data = gnutls_datum_t(cast(c_char_p(buffer), POINTER(c_ubyte)), c_uint(len(buffer)))
        # int gnutls_x509_crl_import (gnutls_x509_crl_t crl, const gnutls_datum_t * data, gnutls_x509_crt_fmt_t format)
        retcode = gnutls_x509_crl_import(self._crl, byref(data), format)
        GNUTLSException.check(retcode)

    @property
    def count(self):
        # int gnutls_x509_crl_get_crt_count (gnutls_x509_crl_t crl)
        retcode = gnutls_x509_crl_get_crt_count(self._crl)
        GNUTLSException.check(retcode)
        return retcode

    # int gnutls_x509_crl_get_crt_serial (gnutls_x509_crl_t crl, int indx, unsigned char * serial, size_t * serial_size, time_t * t)

    @property
    def version(self):
        # int gnutls_x509_crl_get_version (gnutls_x509_crl_t crl)
        retcode = gnutls_x509_crl_get_version(self._crl)
        GNUTLSException.check(retcode)
        return retcode

    @property
    def issuer(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        # int gnutls_x509_crl_get_issuer_dn (gnutls_x509_crl_t crl, char * buf, size_t * sizeof_buf)
        retcode = gnutls_x509_crl_get_issuer_dn(self._crl, dname, byref(size))
        if retcode == GNUTLS_E_SHORT_MEMORY_BUFFER:
            dname = create_string_buffer(size.value)
            retcode = gnutls_x509_crl_get_issuer_dn(self._crl, dname, byref(size))
        GNUTLSException.check(retcode)
        return X509Name(dname.value)

    def __del__(self):
        self.__deinit(self._crl)


