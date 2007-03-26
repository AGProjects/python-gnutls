# Copyright (C) 2007 AG Projects
#

"""GNUTLS crypto support"""

# TODO: better error handling and check the error hierarchy

__all__ = ['X509Name', 'X509Certificate', 'X509CRL', 'X509PrivateKey', 'DHParams', 'RSAParams']

import re
from ctypes import *

from gnutls.constants import X509_FMT_DER, X509_FMT_PEM
from gnutls.errors import *

from gnutls.library.constants import GNUTLS_E_SHORT_MEMORY_BUFFER
from gnutls.library.types import *
from gnutls.library.functions import *


class X509NameMeta(type):
    long_names = {'country': 'C',
                  'state': 'ST',
                  'locality': 'L',
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


class X509Certificate(object):

    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_x509_crt_deinit
        instance._c_object = gnutls_x509_crt_t()
        return instance

    def __init__(self, buffer, format=X509_FMT_PEM):
        if format not in (X509_FMT_PEM, X509_FMT_DER):
            raise ValueError("Incorrect format: %r" % format)
        retcode = gnutls_x509_crt_init(byref(self._c_object))
        GNUTLSException.check(retcode)
        if isinstance(buffer, gnutls_datum_t): ## accept raw certificate data in GNUTLS' datum_t format
            data = buffer
        else:
            data = gnutls_datum_t(cast(c_char_p(buffer), POINTER(c_ubyte)), c_uint(len(buffer)))
        retcode = gnutls_x509_crt_import(self._c_object, byref(data), format)
        GNUTLSException.check(retcode)

    def __del__(self):
        self.__deinit(self._c_object)

    @property
    def subject(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        retcode = gnutls_x509_crt_get_dn(self._c_object, dname, byref(size))
        if retcode == GNUTLS_E_SHORT_MEMORY_BUFFER:
            dname = create_string_buffer(size.value)
            retcode = gnutls_x509_crt_get_dn(self._c_object, dname, byref(size))
        GNUTLSException.check(retcode)
        return X509Name(dname.value)

    @property
    def issuer(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        retcode = gnutls_x509_crt_get_issuer_dn(self._c_object, dname, byref(size))
        if retcode == GNUTLS_E_SHORT_MEMORY_BUFFER:
            dname = create_string_buffer(size.value)
            retcode = gnutls_x509_crt_get_issuer_dn(self._c_object, dname, byref(size))
        GNUTLSException.check(retcode)
        return X509Name(dname.value)

    @property
    def serial_number(self):
        size = c_size_t(1)
        serial = c_ulong()
        retcode = gnutls_x509_crt_get_serial(self._c_object, cast(byref(serial), c_void_p), byref(size))
        if retcode == GNUTLS_E_SHORT_MEMORY_BUFFER:
            import struct, sys
            serial = create_string_buffer(size.value * sizeof(c_void_p))
            retcode = gnutls_x509_crt_get_serial(self._c_object, cast(serial, c_void_p), byref(size))
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
        retcode = gnutls_x509_crt_get_activation_time(self._c_object)
        if retcode == -1:
            raise GNUTLSError("cannot retrieve activation time")
        GNUTLSException.check(retcode)
        return retcode

    @property
    def expiration_time(self):
        retcode = gnutls_x509_crt_get_expiration_time(self._c_object)
        if retcode == -1:
            raise GNUTLSError("cannot retrieve expiration time")
        GNUTLSException.check(retcode)
        return retcode

    @property
    def version(self):
        retcode = gnutls_x509_crt_get_version(self._c_object)
        GNUTLSException.check(retcode)
        return retcode

    def has_issuer(self, issuer):
        """Return True if the certificate was issued by the given issuer, False otherwise."""
        if not isinstance(issuer, X509Certificate):
            raise TypeError("issuer must be a X509Certificate object")
        retcode = gnutls_x509_crt_check_issuer(self._c_object, issuer._c_object)
        GNUTLSException.check(retcode)
        return bool(retcode)

    def has_hostname(self, hostname):
        """Return True if the hostname matches the DNSName/IPAddress subject alternative name extension
           of this certificate, False otherwise."""
        # see http://www.ietf.org/rfc/rfc2459.txt, section 4.2.1.7 Subject Alternative Name
        retcode = gnutls_x509_crt_check_hostname(self._c_object, hostname)
        GNUTLSException.check(retcode)
        return bool(retcode)

    def check_issuer(self, issuer):
        """Raise CertificateError if certificate was not issued by the given issuer"""
        if not self.has_issuer(issuer):
            raise CertificateError("certificate issuer doesn't match")

    def check_hostname(self, hostname):
        """Raise CertificateError if the certificate DNSName/IPAddress subject alternative name extension
           doesn't match the given hostname"""
        if not self.has_hostname(hostname):
            raise CertificateError("certificate doesn't match hostname")


class X509PrivateKey(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_x509_privkey_deinit
        instance._c_object = gnutls_x509_privkey_t()
        return instance

    def __init__(self, buffer, format=X509_FMT_PEM):
        if format not in (X509_FMT_PEM, X509_FMT_DER):
            raise ValueError("Incorrect format: %r" % format)
        retcode = gnutls_x509_privkey_init(byref(self._c_object))
        GNUTLSException.check(retcode)
        data = gnutls_datum_t(cast(c_char_p(buffer), POINTER(c_ubyte)), c_uint(len(buffer)))
        retcode = gnutls_x509_privkey_import(self._c_object, byref(data), format)
        GNUTLSException.check(retcode)

    def __del__(self):
        self.__deinit(self._c_object)


class X509CRL(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_x509_crl_deinit
        instance._c_object = gnutls_x509_crl_t()
        return instance

    def __init__(self, buffer, format=X509_FMT_PEM):
        if format not in (X509_FMT_PEM, X509_FMT_DER):
            raise ValueError("Incorrect format: %r" % format)
        retcode = gnutls_x509_crl_init(byref(self._c_object))
        GNUTLSException.check(retcode)
        data = gnutls_datum_t(cast(c_char_p(buffer), POINTER(c_ubyte)), c_uint(len(buffer)))
        retcode = gnutls_x509_crl_import(self._c_object, byref(data), format)
        GNUTLSException.check(retcode)

    def __del__(self):
        self.__deinit(self._c_object)

    @property
    def count(self):
        retcode = gnutls_x509_crl_get_crt_count(self._c_object)
        GNUTLSException.check(retcode)
        return retcode

    # int gnutls_x509_crl_get_crt_serial (gnutls_x509_crl_t crl, int indx, unsigned char * serial, size_t * serial_size, time_t * t)

    @property
    def version(self):
        retcode = gnutls_x509_crl_get_version(self._c_object)
        GNUTLSException.check(retcode)
        return retcode

    @property
    def issuer(self):
        size = c_size_t(256)
        dname = create_string_buffer(size.value)
        retcode = gnutls_x509_crl_get_issuer_dn(self._c_object, dname, byref(size))
        if retcode == GNUTLS_E_SHORT_MEMORY_BUFFER:
            dname = create_string_buffer(size.value)
            retcode = gnutls_x509_crl_get_issuer_dn(self._c_object, dname, byref(size))
        GNUTLSException.check(retcode)
        return X509Name(dname.value)

    def is_revoked(self, cert):
        """Return True if certificate is revoked, False otherwise"""
        if not isinstance(cert, X509Certificate):
            raise TypeError("cert must be a X509Certificate object")
        retcode = gnutls_x509_crt_check_revocation(cert._c_object, byref(self._c_object), 1)
        GNUTLSException.check(retcode)
        return bool(retcode)

    def check_revocation(self, cert):
        """Raise CertificateError if the given certificate is revoked"""
        if self.is_revoked(cert):
            raise CertificateError("certificate was revoked")


class DHParams(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_dh_params_deinit
        instance._c_object = gnutls_dh_params_t()
        return instance

    def __init__(self, bits=1024):
        gnutls_dh_params_init(byref(self._c_object))
        gnutls_dh_params_generate2(self._c_object, bits)

    def __get__(self, obj, type_=None):
        return self._c_object

    def __set__(self, obj, value):
        raise AttributeError("Read-only attribute")

    def __del__(self):
        self.__deinit(self._c_object)


class RSAParams(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_rsa_params_deinit
        instance._c_object = gnutls_rsa_params_t()
        return instance

    def __init__(self, bits=1024):
        gnutls_rsa_params_init(byref(self._c_object))
        gnutls_rsa_params_generate2(self._c_object, bits)

    def __get__(self, obj, type_=None):
        return self._c_object

    def __set__(self, obj, value):
        raise AttributeError("Read-only attribute")

    def __del__(self):
        self.__deinit(self._c_object)

