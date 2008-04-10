# Copyright (C) 2007-2008 AG Projects. See LICENSE for details.
#

"""GNUTLS connection support"""

__all__ = ['X509Credentials', 'ClientSession', 'ServerSession', 'ServerSessionFactory']

from time import time
from socket import SHUT_RDWR as SOCKET_SHUT_RDWR

from _ctypes import PyObj_FromPtr
from ctypes import *

from gnutls.validators import *
from gnutls.constants import *
from gnutls.crypto import *
from gnutls.errors import *

from gnutls.library.constants import GNUTLS_SERVER, GNUTLS_CLIENT, GNUTLS_CRT_X509
from gnutls.library.constants import GNUTLS_CERT_INVALID, GNUTLS_CERT_REVOKED, GNUTLS_CERT_INSECURE_ALGORITHM
from gnutls.library.constants import GNUTLS_CERT_SIGNER_NOT_FOUND, GNUTLS_CERT_SIGNER_NOT_CA
from gnutls.library.constants import GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE
from gnutls.library.constants import GNUTLS_A_UNKNOWN_CA, GNUTLS_A_INSUFFICIENT_SECURITY
from gnutls.library.constants import GNUTLS_A_CERTIFICATE_EXPIRED, GNUTLS_A_CERTIFICATE_REVOKED
from gnutls.library.constants import GNUTLS_NAME_DNS
from gnutls.library.types     import gnutls_certificate_credentials_t, gnutls_session_t, gnutls_x509_crt_t
from gnutls.library.types     import gnutls_certificate_server_retrieve_function
from gnutls.library.functions import *


@gnutls_certificate_server_retrieve_function
def _retrieve_server_certificate(c_session, retr_st):
    session = PyObj_FromPtr(gnutls_session_get_ptr(c_session))
    identity = session.credentials.select_server_identity(session)
    retr_st.contents.type = GNUTLS_CRT_X509
    retr_st.contents.deinit_all = 0
    if identity is None:
        retr_st.contents.ncerts = 0
    else:
        retr_st.contents.ncerts = 1
        retr_st.contents.cert.x509.contents = identity.cert._c_object
        retr_st.contents.key.x509 = identity.key._c_object
    return 0


class _ServerNameIdentities(dict):
    """Used internally by X509Credentials to map server names to X509 identities for the server name extension"""
    def __init__(self, identities):
        dict.__init__(self)
        for identity in identities:
            self.add(identity)
    def add(self, identity):
        for name in identity.cert.alternative_names.dns:
            self[name.lower()] = identity
        for ip in identity.cert.alternative_names.ip:
            self[ip] = identity
        subject = identity.cert.subject
        if subject.CN is not None:
            self[subject.CN.lower()] = identity
    def get(self, server_name, default=None):
        server_name = server_name.lower()
        if server_name in self:
            return self[server_name]
        for name in (n for n in self if n.startswith('*.')):
            suffix = name[1:]
            if server_name.endswith(suffix) and '.' not in server_name[:-len(suffix)]:
                return self[name]
        return default


class X509Credentials(object):
    DH_BITS  = 1024
    RSA_BITS = 1024

    dh_params  = None
    rsa_params = None

    def __new__(cls, *args, **kwargs):
        c_object = gnutls_certificate_credentials_t()
        gnutls_certificate_allocate_credentials(byref(c_object))
        instance = object.__new__(cls)
        instance.__deinit = gnutls_certificate_free_credentials
        instance._c_object = c_object
        return instance

    @method_args((X509Certificate, none), (X509PrivateKey, none), list_of(X509Certificate), list_of(X509CRL), list_of(X509Identity))
    def __init__(self, cert=None, key=None, trusted=[], crl_list=[], identities=[]):
        """Credentials contain a X509 certificate, a private key, a list of trusted CAs and a list of CRLs (all optional).
        An optional list of additional X509 identities can be specified for applications that need more that one identity"""
        if cert and key:
            gnutls_certificate_set_x509_key(self._c_object, byref(cert._c_object), 1, key._c_object)
        elif (cert, key) != (None, None):
            raise ValueError("Specify neither or both the certificate and private key")
        gnutls_certificate_server_set_retrieve_function(self._c_object, _retrieve_server_certificate)
        self._max_depth = 5
        self._max_bits  = 8200
        self._type = CRED_CERTIFICATE
        self._cert = cert
        self._key = key
        self._identities = tuple(identities)
        self._trusted = ()
        self.add_trusted(trusted)
        self.crl_list = crl_list
        self.server_name_identities = _ServerNameIdentities(identities)
        if cert and key:
            self.server_name_identities.add(X509Identity(cert, key))
        self.session_params = SessionParams(self._type)

    def __del__(self):
        self.__deinit(self._c_object)

    # Methods to alter the credentials at runtime

    @method_args(list_of(X509Certificate))
    def add_trusted(self, trusted):
        size = len(trusted)
        if size > 0:
            ca_list = (gnutls_x509_crt_t * size)(*[cert._c_object for cert in trusted])
            gnutls_certificate_set_x509_trust(self._c_object, cast(byref(ca_list), POINTER(gnutls_x509_crt_t)), size)
            self._trusted = self._trusted + tuple(trusted)

    def generate_dh_params(self, bits=DH_BITS):
        reference = self.dh_params ## keep a reference to preserve it until replaced
        X509Credentials.dh_params  = DHParams(bits)
        del reference

    def generate_rsa_params(self, bits=RSA_BITS):
        reference = self.rsa_params ## keep a reference to preserve it until replaced
        X509Credentials.rsa_params = RSAParams(bits)
        del reference

    # Properties

    @property
    def cert(self):
        return self._cert

    @property
    def key(self):
        return self._key

    @property
    def identities(self):
        return self._identities

    @property
    def trusted(self):
        return self._trusted

    def _get_crl_list(self):
        return self._crl_list
    @method_args(list_of(X509CRL)) 
    def _set_crl_list(self, crl_list):
        self._crl_list = tuple(crl_list)
    crl_list = property(_get_crl_list, _set_crl_list)
    del _get_crl_list, _set_crl_list

    def _get_max_verify_length(self):
        return self._max_depth
    @method_args(int) 
    def _set_max_verify_length(self, max_depth):
        gnutls_certificate_set_verify_limits(self._c_object, self._max_bits, max_depth)
        self._max_depth = max_depth
    max_verify_length = property(_get_max_verify_length, _set_max_verify_length)
    del _get_max_verify_length, _set_max_verify_length

    def _get_max_verify_bits(self):
        return self._max_bits
    @method_args(int) 
    def _set_max_verify_bits(self, max_bits):
        gnutls_certificate_set_verify_limits(self._c_object, max_bits, self._max_depth)
        self._max_bits = max_bits
    max_verify_bits = property(_get_max_verify_bits, _set_max_verify_bits)
    del _get_max_verify_bits, _set_max_verify_bits

    # Methods to select and validate certificates

    def check_certificate(self, cert, cert_name='certificate'):
        """Verify activation, expiration and revocation for the given certificate"""
        now = time()
        if cert.activation_time > now:
            raise CertificateExpiredError("%s is not yet activated" % cert_name)
        if cert.expiration_time < now:
            raise CertificateExpiredError("%s has expired" % cert_name)
        for crl in self.crl_list:
            crl.check_revocation(cert, cert_name=cert_name)

    def select_server_identity(self, session):
        """Select which identity the server will use for a given session. The default selection algorithm uses
        the server name extension. A subclass can overwrite it if a different selection algorithm is desired."""
        server_name = session.server_name
        if server_name is not None:
            return self.server_name_identities.get(server_name)
        elif self.cert and self.key:
            return self ## since we have the cert and key attributes we can behave like a X509Identity
        else:
            return None


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
        self._protocols = ProtocolListValidator(protocols)
    protocols = property(_get_protocols, _set_protocols)
    del _get_protocols, _set_protocols

    def _get_kx_algorithms(self):
        return self._kx_algorithms
    def _set_kx_algorithms(self, algorithms):
        cred_type = self._credentials_type
        algorithms = KeyExchangeListValidator(algorithms)
        invalid = set(algorithms) - self._all_kx_algorithms[cred_type]
        if invalid:
            raise ValueError("Cannot specify %r with %r credentials" % (list(invalid), cred_type))
        self._kx_algorithms = algorithms
    kx_algorithms = property(_get_kx_algorithms, _set_kx_algorithms)
    del _get_kx_algorithms, _set_kx_algorithms

    def _get_ciphers(self):
        return self._ciphers
    def _set_ciphers(self, ciphers):
        self._ciphers = CipherListValidator(ciphers)
    ciphers = property(_get_ciphers, _set_ciphers)
    del _get_ciphers, _set_ciphers

    def _get_mac_algorithms(self):
        return self._mac_algorithms
    def _set_mac_algorithms(self, algorithms):
        self._mac_algorithms = MACListValidator(algorithms)
    mac_algorithms = property(_get_mac_algorithms, _set_mac_algorithms)
    del _get_mac_algorithms, _set_mac_algorithms

    def _get_compressions(self):
        return self._compressions
    def _set_compressions(self, compressions):
        self._compressions = CompressionListValidator(compressions)
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
        gnutls_init(byref(self._c_object), self.session_type)
        ## Store a pointer to self on the C session
        gnutls_session_set_ptr(self._c_object, id(self))
        # gnutls_dh_set_prime_bits(session, DH_BITS)?
        gnutls_transport_set_ptr(self._c_object, socket.fileno())
        gnutls_handshake_set_private_extensions(self._c_object, 1)
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
    @method_args(X509Credentials)
    def _set_credentials(self, credentials):
        ## Release all credentials, otherwise gnutls will only release an existing credential of
        ## the same type as the one being set and we can end up with multiple credentials in C.
        gnutls_credentials_clear(self._c_object)
        gnutls_credentials_set(self._c_object, credentials._type, cast(credentials._c_object, c_void_p))
        self._credentials = credentials
    credentials = property(_get_credentials, _set_credentials)
    del _get_credentials, _set_credentials

    @property
    def protocol(self):
        return gnutls_protocol_get_name(gnutls_protocol_get_version(self._c_object))

    @property
    def kx_algorithm(self):
        return gnutls_kx_get_name(gnutls_kx_get(self._c_object))

    @property
    def cipher(self):
        return gnutls_cipher_get_name(gnutls_cipher_get(self._c_object))

    @property
    def mac_algorithm(self):
        return gnutls_mac_get_name(gnutls_mac_get(self._c_object))

    @property
    def compression(self):
        return gnutls_compression_get_name(gnutls_compression_get(self._c_object))

    @property
    def peer_certificate(self):
        if gnutls_certificate_type_get(self._c_object) != GNUTLS_CRT_X509:
            return None
        list_size = c_uint()
        cert_list = gnutls_certificate_get_peers(self._c_object, byref(list_size))
        if list_size.value == 0:
            return None
        cert = cert_list[0]
        return X509Certificate(string_at(cert.data, cert.size), X509_FMT_DER)

    # Status checking after an operation was interrupted (these properties are
    # only useful to check after an operation was interrupted, otherwise their
    # value is meaningless).

    @property
    def interrupted_while_writing(self):
        """True if an operation was interrupted while writing"""
        return gnutls_record_get_direction(self._c_object)==1

    @property
    def interrupted_while_reading(self):
        """True if an operation was interrupted while reading"""
        return gnutls_record_get_direction(self._c_object)==0

    # Session methods

    def _update_params(self):
        """Update the priorities of the session params using the credentials."""
        def c_priority_list(priorities):
            size = len(priorities) + 1
            return (c_int * size)(*priorities)
        session_params = self.credentials.session_params
        # protocol order in the priority list is irrelevant (it always uses newer protocols first)
        # the protocol list only specifies what protocols are to be enabled.
        gnutls_protocol_set_priority(self._c_object, c_priority_list(session_params.protocols))
        gnutls_kx_set_priority(self._c_object, c_priority_list(session_params.kx_algorithms))
        gnutls_cipher_set_priority(self._c_object, c_priority_list(session_params.ciphers))
        gnutls_mac_set_priority(self._c_object, c_priority_list(session_params.mac_algorithms))
        gnutls_compression_set_priority(self._c_object, c_priority_list(session_params.compressions))

    def handshake(self):
        gnutls_handshake(self._c_object)

    #@method_args((basestring, buffer))
    def send(self, data):
        data = str(data)
        return gnutls_record_send(self._c_object, data, len(data))

    def sendall(self, data):
        size = len(data)
        while size > 0:
            sent = self.send(data[-size:])
            size -= sent

    def recv(self, limit):
        data = create_string_buffer(limit)
        size = gnutls_record_recv(self._c_object, data, limit)
        return data[:size]

    def send_alert(self, exception):
        alertdict = {
            CertificateError: GNUTLS_A_BAD_CERTIFICATE,
            CertificateAuthorityError: GNUTLS_A_UNKNOWN_CA,
            CertificateSecurityError: GNUTLS_A_INSUFFICIENT_SECURITY,
            CertificateExpiredError: GNUTLS_A_CERTIFICATE_EXPIRED,
            CertificateRevokedError: GNUTLS_A_CERTIFICATE_REVOKED}
        alert = alertdict.get(exception.__class__)
        if alert:
            gnutls_alert_send(self._c_object, GNUTLS_AL_FATAL, alert)

    @method_args(one_of(SHUT_RDWR, SHUT_WR))
    def bye(self, how=SHUT_RDWR):
        gnutls_bye(self._c_object, how)

    def shutdown(self, how=SOCKET_SHUT_RDWR):
        self.socket.shutdown(how)

    def close(self):
        self.socket.close()

    def verify_peer(self):
        status = c_uint()
        gnutls_certificate_verify_peers2(self._c_object, byref(status))
        status = status.value
        if status & GNUTLS_CERT_INVALID:
            raise CertificateError("peer certificate is invalid")
        elif status & GNUTLS_CERT_SIGNER_NOT_FOUND:
            raise CertificateAuthorityError("peer certificate signer not found")
        elif status & GNUTLS_CERT_SIGNER_NOT_CA:
            raise CertificateAuthorityError("peer certificate signer is not a CA")
        elif status & GNUTLS_CERT_INSECURE_ALGORITHM:
            raise CertificateSecurityError("peer certificate uses an insecure algorithm")
        elif status & GNUTLS_CERT_REVOKED:
            raise CertificateRevokedError("peer certificate was revoked")


class ClientSession(Session):
    session_type = GNUTLS_CLIENT

    def __init__(self, socket, credentials, server_name=None):
        Session.__init__(self, socket, credentials)
        self._server_name = None
        if server_name is not None:
            self.server_name = server_name

    def _get_server_name(self):
        return self._server_name
    @method_args(str)
    def _set_server_name(self, server_name):
        gnutls_server_name_set(self._c_object, GNUTLS_NAME_DNS, c_char_p(server_name), len(server_name))
        self._server_name = server_name
    server_name = property(_get_server_name, _set_server_name)
    del _get_server_name, _set_server_name


class ServerSession(Session):
    session_type = GNUTLS_SERVER

    def __init__(self, socket, credentials):
        Session.__init__(self, socket, credentials)
        gnutls_certificate_server_set_request(self._c_object, CERT_REQUEST)

    @property
    def server_name(self):
        data_length = c_size_t(256)
        data = create_string_buffer(data_length.value)
        hostname_type = c_uint()
        for i in xrange(2**16):
            try:
                gnutls_server_name_get(self._c_object, data, byref(data_length), byref(hostname_type), i)
            except RequestedDataNotAvailable:
                break
            except MemoryError:
                data_length.value += 1 ## one extra byte for the terminating 0
                data = create_string_buffer(data_length.value)
                gnutls_server_name_get(self._c_object, data, byref(data_length), byref(hostname_type), i)
            if hostname_type.value != GNUTLS_NAME_DNS:
                continue
            return data.value
        return None


class ServerSessionFactory(object):

    def __init__(self, socket, credentials, session_class=ServerSession):
        if not issubclass(session_class, ServerSession):
            raise TypeError, "session_class must be a subclass of ServerSession"
        self.socket = socket
        self.credentials = credentials
        self.session_class = session_class

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

