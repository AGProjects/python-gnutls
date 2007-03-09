# Copyright (C) 2007 AG Projects
#

"""GNUTLS connection support"""

# TODO
# - decide on the best method to check certificate revocation
# - make the server params callback function work
# - more tests

__all__ = ['X509Credentials', 'ClientSession', 'ServerSession', 'ServerSessionFactory']

import time

from ctypes import *

from gnutls.errors import *
from gnutls.crypto import *
from gnutls.library.constants import *
from gnutls.library.types import *
from gnutls.library.functions import *


class X509Credentials(object):

    def __init__(self, cert, key, trusted=[], crl_list=[]):
        '''Credentials object containing an X509 certificate, a private key and 
           optionally a list of trusted CAs and a list of CRLs.'''
        self.__deinit = gnutls_certificate_free_credentials
        trusted = tuple(trusted)
        crl_list = tuple(crl_list)
        self._cred = gnutls_certificate_credentials_t()
        retcode = gnutls_certificate_allocate_credentials(byref(self._cred))
        GNUTLSException.check(retcode)
        # int gnutls_certificate_set_x509_key (gnutls_certificate_credentials_t res, gnutls_x509_crt_t * cert_list, int cert_list_size, gnutls_x509_privkey_t key)
        retcode = gnutls_certificate_set_x509_key(self._cred, byref(cert._cert), 1, key._key)
        GNUTLSException.check(retcode)
        if trusted:
            # int gnutls_certificate_set_x509_trust (gnutls_certificate_credentials_t res, gnutls_x509_crt_t * ca_list, int ca_list_size)
            size = len(trusted)
            block = (gnutls_x509_crt_t * size)() ## declare the array of gnutls_x509_crt_t elements
            for i in range(size): block[i] = trusted[i]._cert
            retcode = gnutls_certificate_set_x509_trust(self._cred, cast(byref(block), POINTER(gnutls_x509_crt_t)), size)
            GNUTLSException.check(retcode)
        self._trusted = trusted
        self._crl_list = crl_list
        self._max_depth = 5
        self._max_bits = 8200
        self._type = GNUTLS_CRD_CERTIFICATE

    def __del__(self):
        self.__deinit(self._cred)

    def set_params_callback(self, callback):
        # void gnutls_certificate_set_params_function (gnutls_certificate_credentials_t res, gnutls_params_function * func)
        callback = gnutls_params_function(callback)
        gnutls_certificate_set_params_function(self._cred, callback)

    def set_dh_params(self, params):
        if type(params) is not DHParams:
            raise TypeError("params must be of type DHParams")
        gnutls_certificate_set_dh_params(self._cred, params._params)

    def set_rsa_params(self, params):
        if type(params) is not RSAParams:
            raise TypeError("params must be of type RSAParams")
        gnutls_certificate_set_rsa_export_params(self._cred, params._params)

    # Properties

    def _get_trusted(self):
        return self._trusted
    def _set_trusted(self, trusted):
        # int gnutls_certificate_set_x509_trust (gnutls_certificate_credentials_t res, gnutls_x509_crt_t * ca_list, int ca_list_size)
        trusted = tuple(trusted)
        size = len(trusted)
        block = (gnutls_x509_crt_t * size)() ## declare the array of gnutls_x509_crt_t elements
        for i in range(size): block[i] = trusted[i]._cert
        retcode = gnutls_certificate_set_x509_trust(self._cred, cast(byref(block), POINTER(gnutls_x509_crt_t)), size)
        GNUTLSException.check(retcode)
        self._trusted = trusted
    trusted = property(_get_trusted, _set_trusted)
    del _get_trusted, _set_trusted

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
        gnutls_certificate_set_verify_limits(self._cred, self._max_bits, max_depth)
        self._max_depth = max_depth
    max_verify_length = property(_get_max_verify_length, _set_max_verify_length)
    del _get_max_verify_length, _set_max_verify_length

    def _get_max_verify_bits(self):
        return self._max_bits
    def _set_max_verify_bits(self, max_bits):
        # void gnutls_certificate_set_verify_limits (gnutls_certificate_credentials_t res, unsigned int max_bits, unsigned int max_depth)
        gnutls_certificate_set_verify_limits(self._cred, _max_bits, self._max_depth)
        self._max_bits = max_bits
    max_verify_bits = property(_get_max_verify_bits, _set_max_verify_bits)
    del _get_max_verify_bits, _set_max_verify_bits


class Session(object):
    '''Abstract class representing a TLS session created from a TCP socket
       and a Credentials object.'''

    def __init__(self, sock, cred):
        '''Must create a self._session GNUTLS structure using the given credentials.
           Also the sock and cred objects must be attached to the Session object.'''
        raise NotImplementedError

    def __getattr__(self, name):
        # called for: fileno, getpeername, getsockname, getsockopt, sesockopt, setblocking, shutdown, close underlying socket methods
        return getattr(self.sock, name)

    # Session properties

    def _get_credentials(self):
        return self.cred
    def _set_credentials(self, credentials):
        # void gnutls_credentials_clear (gnutls_session_t session)
        gnutls_credentials_clear(self._session) # do we need this ? -Mircea
        # int gnutls_credentials_set (gnutls_session_t session, gnutls_credentials_type_t type, void * cred)
        retcode = gnutls_credentials_set(self._session, self.cred._type, cast(self.cred._cred, c_void_p))
        GNUTLSException.check(retcode)
    credentials = property(_get_credentials, _set_credentials)
    del _get_credentials, _set_credentials

    @property
    def key_exchange_algorithm(self):
        kx = gnutls_kx_algorithm_t()
        # gnutls_kx_algorithm_t gnutls_kx_get (gnutls_session_t session)
        kx = gnutls_kx_get(self._session)
        name = create_string_buffer(10)
        # const char * gnutls_kx_get_name (gnutls_kx_algorithm_t algorithm)
        name = gnutls_kx_get_name(kx)
        return name

    @property
    def protocol(self):
        version = gnutls_protocol_t()
        # gnutls_protocol_t gnutls_protocol_get_version (gnutls_session_t session)
        version = gnutls_protocol_get_version(self._session)
        name = create_string_buffer(10)
        # const char * gnutls_protocol_get_name (gnutls_protocol_t version)
        name = gnutls_protocol_get_name(version)
        return name

    @property
    def compression(self):
        method = gnutls_compression_method_t()
        # gnutls_compression_method_t gnutls_compression_get (gnutls_session_t session)
        method = gnutls_compression_get(self._session)
        name = create_string_buffer(10)
        # const char * gnutls_compression_get_name (gnutls_compression_method_t algorithm)
        name = gnutls_compression_get_name(method)
        return name

    @property
    def cipher(self):
        algorithm = gnutls_cipher_algorithm_t()
        # gnutls_cipher_algorithm_t gnutls_cipher_get (gnutls_session_t session)
        algorithm = gnutls_cipher_get(self._session)
        name = create_string_buffer(10)
        # const char * gnutls_compression_get_name (gnutls_compression_method_t algorithm)
        name = gnutls_cipher_get_name(algorithm)
        return name

    @property
    def mac_algorithm(self):
        algorithm = gnutls_mac_algorithm_t()
        # gnutls_mac_algorithm_t gnutls_mac_get (gnutls_session_t session)
        algorithm = gnutls_mac_get(self._session)
        name = create_string_buffer(10)
        # const char * gnutls_mac_get_name (gnutls_mac_algorithm_t algorithm)
        name = gnutls_mac_get_name(algorithm)
        return name

    @property
    def peer_certificate(self):
        # gnutls_certificate_type_t gnutls_certificate_type_get (gnutls_session_t session)
        if (gnutls_certificate_type_get(self._session) != GNUTLS_CRT_X509):
            return
        cert_list = pointer(gnutls_datum_t())
        list_size = c_uint()
        # const gnutls_datum_t * gnutls_certificate_get_peers (gnutls_session_t session, unsigned int * list_size)
        cert_list = gnutls_certificate_get_peers(self._session, byref(list_size))
        if list_size.value == 0:
            return None
        raw_cert = cert_list[0] # we should get the address of the first element in the list
        return X509Certificate(raw_cert, X509_FMT_DER)

    def bye(self, how=GNUTLS_SHUT_RDWR):
        if how not in (GNUTLS_SHUT_RDWR, GNUTLS_SHUT_WR):
            raise ValueError("Invalid argument: " + how)
        retcode = gnutls_bye(self._session, how)
        GNUTLSException.check(retcode)

    def verify_peer(self):
        # int gnutls_certificate_verify_peers2 (gnutls_session_t session, unsigned int * status)
        status = c_uint()
        retcode = gnutls_certificate_verify_peers2(self._session, byref(status))
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
        self.verify_cert(self.peer_certificate)

    def verify_cert(self, peer_cert):
        '''Override this method to make additional checks on the peer certificate.'''
        now = time.time()
        if peer_cert.activation_time > now:
            raise CertificateError("certificate is not yet activated")        
        if peer_cert.expiration_time < now:
            raise CertificateError("certificate has expired")
        for crl in self.cred.crl_list:
            crl.check_revocation(peer_cert)


class ClientSession(Session):

    def __init__(self, sock, cred):
        self.__deinit = gnutls_deinit
        self._session = gnutls_session_t()
        # int gnutls_init (gnutls_session_t * session, gnutls_connection_end_t con_end)
        retcode = gnutls_init(byref(self._session), GNUTLS_CLIENT)
        GNUTLSException.check(retcode)
        # int gnutls_set_default_priority (gnutls_session_t session)
        retcode = gnutls_set_default_priority(self._session)
        GNUTLSException.check(retcode)
        # int gnutls_certificate_type_set_priority (gnutls_session_t session, const int * list) TODO?
        # int gnutls_credentials_set (gnutls_session_t session, gnutls_credentials_type_t type, void * cred)
        retcode = gnutls_credentials_set(self._session, cred._type, cast(cred._cred, c_void_p))
        GNUTLSException.check(retcode)
        # void gnutls_transport_set_ptr (gnutls_session_t session, gnutls_transport_ptr_t ptr)
        gnutls_transport_set_ptr(self._session, sock.fileno())
        self.sock = sock
        self.cred = cred

    def __del__(self):
        self.__deinit(self._session)

    def handshake(self):
        # int gnutls_handshake (gnutls_session_t session)
        retcode = gnutls_handshake(self._session)
        GNUTLSException.check(retcode)

    def send(self, buffer):
        # ssize_t gnutls_record_send (gnutls_session_t session, const void * data, size_t sizeofdata)
        size = c_size_t(len(buffer))
        retcode = gnutls_record_send(self._session, buffer, size.value)
        GNUTLSException.check(retcode)
        return retcode

    def recv(self, bufsize):
        # ssize_t gnutls_record_recv (gnutls_session_t session, void * data, size_t sizeofdata)
        size = c_size_t(bufsize)
        buffer = create_string_buffer(bufsize)
        retcode = gnutls_record_recv(self._session, buffer, size.value)
        GNUTLSException.check(retcode)
        return buffer.value


class ServerSession(Session):

    def __init__(self, sock, cred):
        self.__deinit = gnutls_deinit
        self._session = gnutls_session_t()
        # int gnutls_init (gnutls_session_t * session, gnutls_connection_end_t con_end)
        retcode = gnutls_init(byref(self._session), GNUTLS_SERVER)
        GNUTLSException.check(retcode)
        # int gnutls_set_default_priority (gnutls_session_t session)
        retcode = gnutls_set_default_priority(self._session)
        GNUTLSException.check(retcode)
        # int gnutls_certificate_type_set_priority (gnutls_session_t session, const int * list) TODO?
        # int gnutls_credentials_set (gnutls_session_t session, gnutls_credentials_type_t type, void * cred)
        retcode = gnutls_credentials_set(self._session, cred._type, cast(cred._cred, c_void_p))
        GNUTLSException.check(retcode)
        gnutls_certificate_server_set_request(self._session, GNUTLS_CERT_REQUEST)
        # gnutls_dh_set_prime_bits(session, DH_BITS)?
        # void gnutls_transport_set_ptr (gnutls_session_t session, gnutls_transport_ptr_t ptr)
        gnutls_transport_set_ptr(self._session, sock.fileno())
        self.sock = sock
        self.cred = cred

    def __del__(self):
        self.__deinit(self._session)

    def handshake(self):
        # int gnutls_handshake (gnutls_session_t session)
        retcode = gnutls_handshake(self._session)
        GNUTLSException.check(retcode)

    def send(self, buffer):
        # ssize_t gnutls_record_send (gnutls_session_t session, const void * data, size_t sizeofdata)
        size = c_size_t(len(buffer))
        retcode = gnutls_record_send(self._session, buffer, size.value)
        GNUTLSException.check(retcode)
        return retcode

    def recv(self, bufsize):
        # ssize_t gnutls_record_recv (gnutls_session_t session, void * data, size_t sizeofdata)
        size = c_size_t(bufsize)
        buffer = create_string_buffer(bufsize)
        retcode = gnutls_record_recv(self._session, buffer, size.value)
        GNUTLSException.check(retcode)
        return buffer.value


class ServerSessionFactory(object):
    DH_BITS  = 1024
    RSA_BITS = 1024

    dh_params  = None
    rsa_params = None

    def __init__(self, sock, cred, session_cls=ServerSession):
        if not issubclass(session_cls, ServerSession):
            raise TypeError, "session_cls must be a subclass of ServerSession"
        self.sock = sock
        self.cred = cred
        self.session_cls = session_cls
        self.cred.set_params_callback(self.__get_params)
        self.generate_dh_params()

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def bind(self, address):
        self.sock.bind(address)

    def listen(self, backlog):
        self.sock.listen(backlog)

    def accept(self):
        new_sock, address = self.sock.accept()
        session = self.session_cls(new_sock, self.cred)
        return (session, address)

    def generate_dh_params(self, bits=DH_BITS):
        reference = self.dh_params ## keep a reference to preserve it until replaced
        ServerSessionFactory.dh_params  = DHParams(bits)
        del reference

    def generate_rsa_params(self, bits=RSA_BITS):
        reference = self.rsa_params ## keep a reference to preserve it until replaced
        ServerSessionFactory.rsa_params = RSAParams(bits)
        del reference

    # Callback functions
    def __get_params(self, session, type, st):
        """Callback function that is used when a session requests DH or RSA parameters"""
        # static int get_params( gnutls_session_t session, gnutls_params_type_t type, gnutls_params_st *st)
        # see example http://www.gnu.org/software/gnutls/manual/gnutls.html#Parameters-stored-in-credentials -Mircea
        print "get_params callback:", session, type, st
        return 0

