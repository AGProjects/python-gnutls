# Copyright (C) 2007 AG Projects
#

"""GNUTLS connection support"""

# TODO
# - make the server params callback function work

__all__ = ['X509Credentials', 'ClientSession', 'ServerSession', 'ServerSessionFactory']

from time import time
from socket import SHUT_RDWR as SOCKET_SHUT_RDWR

from ctypes import *

from gnutls.validators import *
from gnutls.constants import *
from gnutls.crypto import *
from gnutls.errors import *

from gnutls.library.constants import GNUTLS_SERVER, GNUTLS_CLIENT, GNUTLS_CRT_X509
from gnutls.library.constants import GNUTLS_CERT_INVALID, GNUTLS_CERT_REVOKED, GNUTLS_CERT_INSECURE_ALGORITHM
from gnutls.library.constants import GNUTLS_CERT_SIGNER_NOT_FOUND, GNUTLS_CERT_SIGNER_NOT_CA
from gnutls.library.constants import * # temporary -Dan
from gnutls.library.types import *
from gnutls.library.functions import *


class X509Credentials(object):
    DH_BITS  = 1024
    RSA_BITS = 1024

    dh_params  = None
    rsa_params = None

    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__deinit = gnutls_certificate_free_credentials
        instance._c_object = gnutls_certificate_credentials_t()
        return instance

    def __init__(self, cert=None, key=None, trusted=[], crl_list=[]):
        """Credentials object containing an X509 certificate, a private key and 
           optionally a list of trusted CAs and a list of CRLs."""
        retcode = gnutls_certificate_allocate_credentials(byref(self._c_object))
        GNUTLSException.check(retcode)
        # int gnutls_certificate_set_x509_key (gnutls_certificate_credentials_t res, gnutls_x509_crt_t * cert_list, int cert_list_size, gnutls_x509_privkey_t key)
        if cert and key:
            retcode = gnutls_certificate_set_x509_key(self._c_object, byref(cert._c_object), 1, key._c_object)
            GNUTLSException.check(retcode)
        elif (cert, key) != (None, None):
            raise ValueError("Specify neither or both the certificate and private key")
        # this generates core dumping - gnutls_certificate_set_params_function(self._c_object, gnutls_params_function(self.__get_params))
        self._max_depth = 5
        self._max_bits  = 8200
        self._type = CRED_CERTIFICATE
        self._trusted = ()
        self.cert = cert
        self.key = key
        self.add_trusted(trusted)
        self.crl_list = crl_list
        self.session_params = SessionParams(self._type)

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


class SessionParams(object):
    _default_kx_algorithms = {
        CRED_CERTIFICATE: (KX_RSA, KX_DHE_DSS, KX_DHE_RSA),
        CRED_ANON: (KX_ANON_DH,)}
    _all_kx_algorithms = {
        CRED_CERTIFICATE: set((KX_RSA, KX_DHE_DSS, KX_DHE_RSA, KX_RSA_EXPORT)),
        CRED_ANON: set((KX_ANON_DH,))}

    def __new__(cls, credentials_type):
        if credentials_type not in cls._default_kx_algorithms:
            raise TypeError("Unknown credentials type: %r" % credentials_type)
        return object.__new__(cls)

    def __init__(self, credentials_type):
        self._credentials_type = credentials_type
        self._protocols = (PROTO_TLS1_1, PROTO_TLS1_0, PROTO_SSL3)
        self._kx_algorithms = self._default_kx_algorithms[credentials_type]
        self._ciphers = (CIPHER_AES_128_CBC, CIPHER_3DES_CBC, CIPHER_ARCFOUR_128)
        self._mac_algorithms = (MAC_SHA1, MAC_MD5, MAC_RMD160)
        self._compressions = (COMP_NULL,)

    def _get_protocols(self):
        return self._protocols
    def _set_protocols(self, protocols):
        self._protocols = ProtocolValidator(protocols)
    protocols = property(_get_protocols, _set_protocols)
    del _get_protocols, _set_protocols

    def _get_kx_algorithms(self):
        return self._kx_algorithms
    def _set_kx_algorithms(self, algorithms):
        cred_type = self._credentials_type
        algorithms = KeyExchangeValidator(algorithms)
        invalid = set(algorithms) - self._all_kx_algorithms[cred_type]
        if invalid:
            raise ValueError("Cannot specify %r with %r credentials" % (list(invalid), cred_type))
        self._kx_algorithms = algorithms
    kx_algorithms = property(_get_kx_algorithms, _set_kx_algorithms)
    del _get_kx_algorithms, _set_kx_algorithms

    def _get_ciphers(self):
        return self._ciphers
    def _set_ciphers(self, ciphers):
        self._ciphers = CipherValidator(ciphers)
    ciphers = property(_get_ciphers, _set_ciphers)
    del _get_ciphers, _set_ciphers

    def _get_mac_algorithms(self):
        return self._mac_algorithms
    def _set_mac_algorithms(self, alogrithms):
        self._mac_algorithms = MACValidator(alogrithms)
    mac_algorithms = property(_get_mac_algorithms, _set_mac_algorithms)
    del _get_mac_algorithms, _set_mac_algorithms

    def _get_compressions(self):
        return self._compressions
    def _set_compressions(self, compressions):
        self._compressions = CompressionValidator(compressions)
    compressions = property(_get_compressions, _set_compressions)
    del _get_compressions, _set_compressions


class Session(object):
    """Abstract class representing a TLS session created from a TCP socket
       and a Credentials object."""

    session_type = None ## placeholder for GNUTLS_SERVER or GNUTLS_CLIENT as defined by subclass

    def __new__(cls, *args, **kwargs):
        if cls is Session:
            raise RuntimeError("Session cannot be instantiated directly")
        instance = object.__new__(cls)
        instance.__deinit = gnutls_deinit
        instance._c_object = gnutls_session_t()
        return instance

    def __init__(self, socket, credentials):
        # int gnutls_init (gnutls_session_t * session, gnutls_connection_end_t con_end)
        retcode = gnutls_init(byref(self._c_object), self.session_type)
        GNUTLSException.check(retcode)
        # int gnutls_certificate_type_set_priority (gnutls_session_t session, const int * list) TODO?
        # gnutls_dh_set_prime_bits(session, DH_BITS)?
        # void gnutls_transport_set_ptr (gnutls_session_t session, gnutls_transport_ptr_t ptr)
        gnutls_transport_set_ptr(self._c_object, socket.fileno())
        self.socket = socket
        self.credentials = credentials
        self._update_params()

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
        # gnutls_kx_algorithm_t gnutls_kx_get (gnutls_session_t session)
        # const char * gnutls_kx_get_name (gnutls_kx_algorithm_t algorithm)
        return gnutls_kx_get_name(gnutls_kx_get(self._c_object))

    @property
    def protocol(self):
        # gnutls_protocol_t gnutls_protocol_get_version (gnutls_session_t session)
        # const char * gnutls_protocol_get_name (gnutls_protocol_t version)
        return gnutls_protocol_get_name(gnutls_protocol_get_version(self._c_object))

    @property
    def compression(self):
        # gnutls_compression_method_t gnutls_compression_get (gnutls_session_t session)
        # const char * gnutls_compression_get_name (gnutls_compression_method_t algorithm)
        return gnutls_compression_get_name(gnutls_compression_get(self._c_object))

    @property
    def cipher(self):
        # gnutls_cipher_algorithm_t gnutls_cipher_get (gnutls_session_t session)
        # const char * gnutls_compression_get_name (gnutls_compression_method_t algorithm)
        return gnutls_cipher_get_name(gnutls_cipher_get(self._c_object))

    @property
    def mac_algorithm(self):
        # gnutls_mac_algorithm_t gnutls_mac_get (gnutls_session_t session)
        # const char * gnutls_mac_get_name (gnutls_mac_algorithm_t algorithm)
        return gnutls_mac_get_name(gnutls_mac_get(self._c_object))

    @property
    def peer_certificate(self):
        # gnutls_certificate_type_t gnutls_certificate_type_get (gnutls_session_t session)
        if (gnutls_certificate_type_get(self._c_object) != GNUTLS_CRT_X509):
            return
        list_size = c_uint()
        # const gnutls_datum_t * gnutls_certificate_get_peers (gnutls_session_t session, unsigned int * list_size)
        cert_list = gnutls_certificate_get_peers(self._c_object, byref(list_size))
        if list_size.value == 0:
            return None
        return X509Certificate(cert_list[0], X509_FMT_DER)

    # Session methods

    def _update_params(self):
        """Update the priorities of the session params using the credentials."""
        def c_priority_list(priorities):
            size = len(priorities) + 1
            return (c_int * size)(*priorities)
        session_params = self.credentials.session_params
        # int gnutls_protocol_set_priority (gnutls_session_t session, const int * list)
        retcode = gnutls_protocol_set_priority(self._c_object, c_priority_list(session_params.protocols))
        GNUTLSException.check(retcode)
        # int gnutls_kx_set_priority (gnutls_session_t session, const int * list)
        retcode = gnutls_kx_set_priority(self._c_object, c_priority_list(session_params.kx_algorithms))
        GNUTLSException.check(retcode)
        # int gnutls_cipher_set_priority (gnutls_session_t session, const int * list)
        retcode = gnutls_cipher_set_priority(self._c_object, c_priority_list(session_params.ciphers))
        GNUTLSException.check(retcode)
        # int gnutls_mac_set_priority (gnutls_session_t session, const int * list)
        retcode = gnutls_mac_set_priority(self._c_object, c_priority_list(session_params.mac_algorithms))
        GNUTLSException.check(retcode)
        # int gnutls_compression_set_priority (gnutls_session_t session, const int * list)
        retcode = gnutls_compression_set_priority(self._c_object, c_priority_list(session_params.compressions))
        GNUTLSException.check(retcode)

    def handshake(self):
        # int gnutls_handshake (gnutls_session_t session)
        retcode = gnutls_handshake(self._c_object)
        GNUTLSException.check(retcode)

    def send(self, data):
        # ssize_t gnutls_record_send (gnutls_session_t session, const void * data, size_t sizeofdata)
        data = str(data)
        size = c_size_t(len(data))
        retcode = gnutls_record_send(self._c_object, data, size.value)
        GNUTLSException.check(retcode)
        return retcode

    def recv(self, limit):
        # ssize_t gnutls_record_recv (gnutls_session_t session, void * data, size_t sizeofdata)
        size = c_size_t(limit)
        data = create_string_buffer(limit)
        retcode = gnutls_record_recv(self._c_object, data, size.value)
        GNUTLSException.check(retcode)
        return data.value

    def bye(self, how=SHUT_RDWR):
        if how not in (SHUT_RDWR, SHUT_WR):
            raise ValueError("Invalid argument: %s" % how)
        retcode = gnutls_bye(self._c_object, how)
        GNUTLSException.check(retcode)

    def shutdown(self, how=SOCKET_SHUT_RDWR):
        self.socket.shutdown(how)

    def close(self):
        self.socket.close()

    def verify_peer(self):
        # int gnutls_certificate_verify_peers2 (gnutls_session_t session, unsigned int * status)
        status = c_uint()
        retcode = gnutls_certificate_verify_peers2(self._c_object, byref(status))
        GNUTLSException.check(retcode)
        status = status.value
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
        gnutls_certificate_server_set_request(self._c_object, CERT_REQUEST)
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
        ## Generic wrapper for the underlying socket methods and attributes
        return getattr(self.socket, name)

    def bind(self, address):
        self.socket.bind(address)

    def listen(self, backlog):
        self.socket.listen(backlog)

    def accept(self):
        new_sock, address = self.socket.accept()
        session = self.session_class(new_sock, self.credentials)
        return (session, address)

    def shutdown(self, how=SOCKET_SHUT_RDWR):
        self.socket.shutdown(how)

    def close(self):
        self.socket.close()

