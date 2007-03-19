# Copyright (C) 2007 AG Projects
#

"""GNUTLS connection support"""

# TODO
# - decide on the best method to check certificate revocation
# - make the server params callback function work
# - more tests

__all__ = ['X509Credentials', 'ClientSession', 'ServerSession', 'ServerSessionFactory']

from time import time
from socket import SHUT_RDWR

from ctypes import *

from gnutls.errors import *
from gnutls.crypto import *
from gnutls.library.constants import *
from gnutls.library.types import *
from gnutls.library.functions import *


class X509Credentials(object):
    DH_BITS  = 1024
    RSA_BITS = 1024

    dh_params  = None
    rsa_params = None

    def __init__(self, cert=None, key=None, trusted=[], crl_list=[]):
        """Credentials object containing an X509 certificate, a private key and 
           optionally a list of trusted CAs and a list of CRLs."""
        self.__deinit = gnutls_certificate_free_credentials
        self._c_object = gnutls_certificate_credentials_t()
        retcode = gnutls_certificate_allocate_credentials(byref(self._c_object))
        GNUTLSException.check(retcode)
        if (key is None) != (cert is None):
            raise ValueError("Specify neither or both of private key and certificate")
        # int gnutls_certificate_set_x509_key (gnutls_certificate_credentials_t res, gnutls_x509_crt_t * cert_list, int cert_list_size, gnutls_x509_privkey_t key)
        if cert and key:
            retcode = gnutls_certificate_set_x509_key(self._c_object, byref(cert._c_object), 1, key._c_object)
            GNUTLSException.check(retcode)
        # this generates core dumping - gnutls_certificate_set_params_function(self._c_object, gnutls_params_function(self.__get_params))
        self._trusted = ()
        self.cert = cert
        self.key = key
        self.add_trusted(trusted)
        self.crl_list = crl_list
        self._max_depth = 5
        self._max_bits  = 8200
        self._type = GNUTLS_CRD_CERTIFICATE

    def __del__(self):
        self.__deinit(self._c_object)

    def add_trusted(self, trusted):
        # int gnutls_certificate_set_x509_trust (gnutls_certificate_credentials_t res, gnutls_x509_crt_t * ca_list, int ca_list_size)
        size = len(trusted)
        if size > 0:
            block = (gnutls_x509_crt_t * size)() ## declare the array of gnutls_x509_crt_t elements
            for i in range(size):
                block[i] = trusted[i]._c_object
            retcode = gnutls_certificate_set_x509_trust(self._c_object, cast(byref(block), POINTER(gnutls_x509_crt_t)), size)
            GNUTLSException.check(retcode)
            self._trusted = self._trusted + tuple(trusted)

    def generate_dh_params(self, bits=DH_BITS):
        reference = self.dh_params ## keep a reference to preserve it until replaced
        X509Credentials.dh_params  = DHParams(bits)
        del reference

    def generate_rsa_params(self, bits=RSA_BITS):
        reference = self.rsa_params ## keep a reference to preserve it until replaced
        X509Credentials.rsa_params = RSAParams(bits)
        del reference

    def __get_params(self, session, type, st):
        """Callback function that is used when a session requests DH or RSA parameters"""
        # static int get_params( gnutls_session_t session, gnutls_params_type_t type, gnutls_params_st *st)
        # see example http://www.gnu.org/software/gnutls/manual/gnutls.html#Parameters-stored-in-credentials -Mircea
        print "get_params callback:", session, type, st
        return 0

    # Properties

    @property
    def trusted(self):
        return self._trusted

    def _get_crl_list(self):
        return self._crl_list
    def _set_crl_list(self, crl_list):
        self._crl_list = tuple(crl_list)
    crl_list = property(_get_crl_list, _set_crl_list)
    del _get_crl_list, _set_crl_list

    def _get_max_verify_length(self):
        return self._max_depth
    def _set_max_verify_length(self, max_depth):
        # void gnutls_certificate_set_verify_limits (gnutls_certificate_credentials_t res, unsigned int max_bits, unsigned int max_depth)
        gnutls_certificate_set_verify_limits(self._c_object, self._max_bits, max_depth)
        self._max_depth = max_depth
    max_verify_length = property(_get_max_verify_length, _set_max_verify_length)
    del _get_max_verify_length, _set_max_verify_length

    def _get_max_verify_bits(self):
        return self._max_bits
    def _set_max_verify_bits(self, max_bits):
        # void gnutls_certificate_set_verify_limits (gnutls_certificate_credentials_t res, unsigned int max_bits, unsigned int max_depth)
        gnutls_certificate_set_verify_limits(self._c_object, _max_bits, self._max_depth)
        self._max_bits = max_bits
    max_verify_bits = property(_get_max_verify_bits, _set_max_verify_bits)
    del _get_max_verify_bits, _set_max_verify_bits

    def check_certificate(self, cert):
        """Override this method to make additional checks on the certificate."""
        now = time()
        if cert.activation_time > now:
            raise CertificateError("certificate is not yet activated")        
        if cert.expiration_time < now:
            raise CertificateError("certificate has expired")
        for crl in self.crl_list:
            crl.check_revocation(cert)


class Session(object):
    """Abstract class representing a TLS session created from a TCP socket
       and a Credentials object."""

    session_type = None ## placeholder for GNUTLS_SERVER or GNUTLS_CLIENT as defined by subclass

    def __init__(self, socket, credentials):
        self.__deinit = gnutls_deinit
        self._c_object = gnutls_session_t()
        if self.__class__ is Session:
            raise RuntimeError("Session cannot be instantiated directly")
        # int gnutls_init (gnutls_session_t * session, gnutls_connection_end_t con_end)
        retcode = gnutls_init(byref(self._c_object), self.session_type)
        GNUTLSException.check(retcode)
        # int gnutls_set_default_priority (gnutls_session_t session)
        retcode = gnutls_set_default_priority(self._c_object)
        GNUTLSException.check(retcode)
        # int gnutls_certificate_type_set_priority (gnutls_session_t session, const int * list) TODO?
        # gnutls_dh_set_prime_bits(session, DH_BITS)?
        # void gnutls_transport_set_ptr (gnutls_session_t session, gnutls_transport_ptr_t ptr)
        gnutls_transport_set_ptr(self._c_object, socket.fileno())
        self.socket = socket
        self.credentials = credentials

    def __del__(self):
        self.__deinit(self._c_object)

    def __getattr__(self, name):
        ## Generic wrapper for the underlying socket methods and attributes.
        return getattr(self.socket, name)

    # Session properties

    def _get_credentials(self):
        return self._credentials
    def _set_credentials(self, credentials):
        # void gnutls_credentials_clear (gnutls_session_t session)
        gnutls_credentials_clear(self._c_object) # do we need this ? -Mircea
        # int gnutls_credentials_set (gnutls_session_t session, gnutls_credentials_type_t type, void * cred)
        retcode = gnutls_credentials_set(self._c_object, credentials._type, cast(credentials._c_object, c_void_p))
        GNUTLSException.check(retcode)
        self._credentials = credentials
    credentials = property(_get_credentials, _set_credentials)
    del _get_credentials, _set_credentials

    @property
    def key_exchange_algorithm(self):
        kx = gnutls_kx_algorithm_t()
        # gnutls_kx_algorithm_t gnutls_kx_get (gnutls_session_t session)
        kx = gnutls_kx_get(self._c_object)
        name = create_string_buffer(10)
        # const char * gnutls_kx_get_name (gnutls_kx_algorithm_t algorithm)
        name = gnutls_kx_get_name(kx)
        return name

    @property
    def protocol(self):
        version = gnutls_protocol_t()
        # gnutls_protocol_t gnutls_protocol_get_version (gnutls_session_t session)
        version = gnutls_protocol_get_version(self._c_object)
        name = create_string_buffer(10)
        # const char * gnutls_protocol_get_name (gnutls_protocol_t version)
        name = gnutls_protocol_get_name(version)
        return name

    @property
    def compression(self):
        method = gnutls_compression_method_t()
        # gnutls_compression_method_t gnutls_compression_get (gnutls_session_t session)
        method = gnutls_compression_get(self._c_object)
        name = create_string_buffer(10)
        # const char * gnutls_compression_get_name (gnutls_compression_method_t algorithm)
        name = gnutls_compression_get_name(method)
        return name

    @property
    def cipher(self):
        algorithm = gnutls_cipher_algorithm_t()
        # gnutls_cipher_algorithm_t gnutls_cipher_get (gnutls_session_t session)
        algorithm = gnutls_cipher_get(self._c_object)
        name = create_string_buffer(10)
        # const char * gnutls_compression_get_name (gnutls_compression_method_t algorithm)
        name = gnutls_cipher_get_name(algorithm)
        return name

    @property
    def mac_algorithm(self):
        algorithm = gnutls_mac_algorithm_t()
        # gnutls_mac_algorithm_t gnutls_mac_get (gnutls_session_t session)
        algorithm = gnutls_mac_get(self._c_object)
        name = create_string_buffer(10)
        # const char * gnutls_mac_get_name (gnutls_mac_algorithm_t algorithm)
        name = gnutls_mac_get_name(algorithm)
        return name

    @property
    def peer_certificate(self):
        # gnutls_certificate_type_t gnutls_certificate_type_get (gnutls_session_t session)
        if (gnutls_certificate_type_get(self._c_object) != GNUTLS_CRT_X509):
            return
        cert_list = pointer(gnutls_datum_t())
        list_size = c_uint()
        # const gnutls_datum_t * gnutls_certificate_get_peers (gnutls_session_t session, unsigned int * list_size)
        cert_list = gnutls_certificate_get_peers(self._c_object, byref(list_size))
        if list_size.value == 0:
            return None
        raw_cert = cert_list[0] # we should get the address of the first element in the list
        return X509Certificate(raw_cert, X509_FMT_DER)

    # Session methods

    def handshake(self):
        # int gnutls_handshake (gnutls_session_t session)
        retcode = gnutls_handshake(self._c_object)
        GNUTLSException.check(retcode)

    def send(self, buffer):
        # ssize_t gnutls_record_send (gnutls_session_t session, const void * data, size_t sizeofdata)
        size = c_size_t(len(buffer))
        retcode = gnutls_record_send(self._c_object, buffer, size.value)
        GNUTLSException.check(retcode)
        return retcode

    def recv(self, bufsize):
        # ssize_t gnutls_record_recv (gnutls_session_t session, void * data, size_t sizeofdata)
        size = c_size_t(bufsize)
        buffer = create_string_buffer(bufsize)
        retcode = gnutls_record_recv(self._c_object, buffer, size.value)
        GNUTLSException.check(retcode)
        return buffer.value

    def bye(self, how=GNUTLS_SHUT_RDWR):
        if how not in (GNUTLS_SHUT_RDWR, GNUTLS_SHUT_WR):
            raise ValueError("Invalid argument: %s" % how)
        retcode = gnutls_bye(self._c_object, how)
        GNUTLSException.check(retcode)

    def shutdown(self, how=SHUT_RDWR):
        self.socket.shutdown(how)

    def verify_peer(self):
        # int gnutls_certificate_verify_peers2 (gnutls_session_t session, unsigned int * status)
        status = c_uint()
        retcode = gnutls_certificate_verify_peers2(self._c_object, byref(status))
        GNUTLSException.check(retcode)
        status = int(status.value)
        if status & GNUTLS_CERT_INVALID:
            raise CertificateError("invalid certificate")
        elif status & GNUTLS_CERT_SIGNER_NOT_FOUND:
            raise CertificateError("couldn't find certificate signer")
        elif status & GNUTLS_CERT_REVOKED:
            raise CertificateError("certificate was revoked")
        elif status & GNUTLS_CERT_SIGNER_NOT_CA:
            raise CertificateError("certificate signer is not a CA")
        elif status & GNUTLS_CERT_INSECURE_ALGORITHM:
            raise CertificateError("insecure algorithm")


class ClientSession(Session):
    session_type = GNUTLS_CLIENT


class ServerSession(Session):
    session_type = GNUTLS_SERVER

    def __init__(self, socket, credentials):
        Session.__init__(self, socket, credentials)
        gnutls_certificate_server_set_request(self._c_object, GNUTLS_CERT_REQUEST)
        # gnutls_dh_set_prime_bits(session, DH_BITS)?


class ServerSessionFactory(object):

    def __init__(self, socket, credentials, session_class=ServerSession):
        if not issubclass(session_class, ServerSession):
            raise TypeError, "session_class must be a subclass of ServerSession"
        self.socket = socket
        self.credentials = credentials
        self.session_class = session_class
        #self.credentials.generate_dh_params()

    def __getattr__(self, name):
        return getattr(self.socket, name)

    def bind(self, address):
        self.socket.bind(address)

    def listen(self, backlog):
        self.socket.listen(backlog)

    def accept(self):
        new_sock, address = self.socket.accept()
        session = self.session_class(new_sock, self.credentials)
        return (session, address)
