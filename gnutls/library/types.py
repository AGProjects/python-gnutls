from ctypes import *

from gnutls.library.constants import gnutls_openpgp_crt_fmt
STRING = c_char_p
from gnutls.library.constants import gnutls_cipher_algorithm_t
from gnutls.library.constants import gnutls_params_type_t
from gnutls.library.constants import gnutls_psk_key_flags
from gnutls.library.constants import gnutls_x509_subject_alt_name_t
from gnutls.library.constants import gnutls_certificate_type_t
from gnutls.library.constants import gnutls_pk_algorithm_t
from gnutls.library.constants import gnutls_certificate_import_flags
from gnutls.library.constants import gnutls_certificate_print_formats
from gnutls.library.constants import gnutls_certificate_verify_flags
from gnutls.library.constants import gnutls_pkcs_encrypt_flags_t


gnutls_openpgp_crt_fmt_t = gnutls_openpgp_crt_fmt
class gnutls_session_int(Structure):
    pass
gnutls_session_t = POINTER(gnutls_session_int)
class gnutls_datum_t(Structure):
    pass
gnutls_openpgp_recv_key_func = CFUNCTYPE(c_int, gnutls_session_t, POINTER(c_ubyte), c_uint, POINTER(gnutls_datum_t))
size_t = c_size_t
gnutls_ia_avp_func = CFUNCTYPE(c_int, gnutls_session_t, c_void_p, STRING, size_t, POINTER(STRING), POINTER(size_t))
class gnutls_ia_server_credentials_st(Structure):
    pass
gnutls_ia_server_credentials_st._fields_ = [
]
gnutls_ia_server_credentials_t = POINTER(gnutls_ia_server_credentials_st)
class gnutls_ia_client_credentials_st(Structure):
    pass
gnutls_ia_client_credentials_st._fields_ = [
]
gnutls_ia_client_credentials_t = POINTER(gnutls_ia_client_credentials_st)
gnutls_transport_ptr_t = c_void_p
gnutls_session_int._fields_ = [
]
class gnutls_dh_params_int(Structure):
    pass
gnutls_dh_params_int._fields_ = [
]
gnutls_dh_params_t = POINTER(gnutls_dh_params_int)
class gnutls_x509_privkey_int(Structure):
    pass
gnutls_x509_privkey_int._fields_ = [
]
gnutls_rsa_params_t = POINTER(gnutls_x509_privkey_int)
class gnutls_priority_st(Structure):
    pass
gnutls_priority_st._fields_ = [
]
gnutls_priority_t = POINTER(gnutls_priority_st)
gnutls_datum_t._fields_ = [
    ('data', POINTER(c_ubyte)),
    ('size', c_uint),
]
class gnutls_params_st(Structure):
    pass
class params(Union):
    pass
params._fields_ = [
    ('dh', gnutls_dh_params_t),
    ('rsa_export', gnutls_rsa_params_t),
]
gnutls_params_st._fields_ = [
    ('type', gnutls_params_type_t),
    ('params', params),
    ('deinit', c_int),
]
gnutls_params_function = CFUNCTYPE(c_int, gnutls_session_t, gnutls_params_type_t, POINTER(gnutls_params_st))
gnutls_oprfi_callback_func = CFUNCTYPE(c_int, gnutls_session_t, c_void_p, size_t, POINTER(c_ubyte), POINTER(c_ubyte))
gnutls_db_store_func = CFUNCTYPE(c_int, c_void_p, gnutls_datum_t, gnutls_datum_t)
gnutls_db_remove_func = CFUNCTYPE(c_int, c_void_p, gnutls_datum_t)
gnutls_db_retr_func = CFUNCTYPE(gnutls_datum_t, c_void_p, gnutls_datum_t)
gnutls_handshake_post_client_hello_func = CFUNCTYPE(c_int, gnutls_session_t)
class gnutls_certificate_credentials_st(Structure):
    pass
gnutls_certificate_credentials_st._fields_ = [
]
gnutls_certificate_credentials_t = POINTER(gnutls_certificate_credentials_st)
gnutls_certificate_server_credentials = gnutls_certificate_credentials_t
gnutls_certificate_client_credentials = gnutls_certificate_credentials_t
class gnutls_anon_server_credentials_st(Structure):
    pass
gnutls_anon_server_credentials_st._fields_ = [
]
gnutls_anon_server_credentials_t = POINTER(gnutls_anon_server_credentials_st)
class gnutls_anon_client_credentials_st(Structure):
    pass
gnutls_anon_client_credentials_st._fields_ = [
]
gnutls_anon_client_credentials_t = POINTER(gnutls_anon_client_credentials_st)
gnutls_x509_privkey_t = POINTER(gnutls_x509_privkey_int)
class gnutls_x509_crl_int(Structure):
    pass
gnutls_x509_crl_int._fields_ = [
]
gnutls_x509_crl_t = POINTER(gnutls_x509_crl_int)
class gnutls_x509_crt_int(Structure):
    pass
gnutls_x509_crt_int._fields_ = [
]
gnutls_x509_crt_t = POINTER(gnutls_x509_crt_int)
gnutls_alloc_function = CFUNCTYPE(c_void_p, size_t)
gnutls_calloc_function = CFUNCTYPE(c_void_p, size_t, size_t)
gnutls_is_secure_function = CFUNCTYPE(c_int, c_void_p)
gnutls_free_function = CFUNCTYPE(None, c_void_p)
gnutls_realloc_function = CFUNCTYPE(c_void_p, c_void_p, size_t)
gnutls_log_func = CFUNCTYPE(None, c_int, STRING)
__ssize_t = c_long
ssize_t = __ssize_t
gnutls_pull_func = CFUNCTYPE(ssize_t, gnutls_transport_ptr_t, c_void_p, size_t)
gnutls_push_func = CFUNCTYPE(ssize_t, gnutls_transport_ptr_t, c_void_p, size_t)
class gnutls_srp_server_credentials_st(Structure):
    pass
gnutls_srp_server_credentials_st._fields_ = [
]
gnutls_srp_server_credentials_t = POINTER(gnutls_srp_server_credentials_st)
class gnutls_srp_client_credentials_st(Structure):
    pass
gnutls_srp_client_credentials_st._fields_ = [
]
gnutls_srp_client_credentials_t = POINTER(gnutls_srp_client_credentials_st)
gnutls_srp_server_credentials_function = CFUNCTYPE(c_int, gnutls_session_t, STRING, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t))
gnutls_srp_client_credentials_function = CFUNCTYPE(c_int, gnutls_session_t, POINTER(STRING), POINTER(STRING))
class gnutls_psk_server_credentials_st(Structure):
    pass
gnutls_psk_server_credentials_st._fields_ = [
]
gnutls_psk_server_credentials_t = POINTER(gnutls_psk_server_credentials_st)
class gnutls_psk_client_credentials_st(Structure):
    pass
gnutls_psk_client_credentials_st._fields_ = [
]
gnutls_psk_client_credentials_t = POINTER(gnutls_psk_client_credentials_st)
gnutls_psk_server_credentials_function = CFUNCTYPE(c_int, gnutls_session_t, STRING, POINTER(gnutls_datum_t))
gnutls_psk_client_credentials_function = CFUNCTYPE(c_int, gnutls_session_t, POINTER(STRING), POINTER(gnutls_datum_t))
class gnutls_openpgp_crt_int(Structure):
    pass
gnutls_openpgp_crt_int._fields_ = [
]
gnutls_openpgp_crt_t = POINTER(gnutls_openpgp_crt_int)
class gnutls_openpgp_privkey_int(Structure):
    pass
gnutls_openpgp_privkey_int._fields_ = [
]
gnutls_openpgp_privkey_t = POINTER(gnutls_openpgp_privkey_int)
class gnutls_retr_st(Structure):
    pass
class cert(Union):
    pass
cert._fields_ = [
    ('x509', POINTER(gnutls_x509_crt_t)),
    ('pgp', gnutls_openpgp_crt_t),
]
class key(Union):
    pass
key._fields_ = [
    ('x509', gnutls_x509_privkey_t),
    ('pgp', gnutls_openpgp_privkey_t),
]
gnutls_retr_st._fields_ = [
    ('type', gnutls_certificate_type_t),
    ('cert', cert),
    ('ncerts', c_uint),
    ('key', key),
    ('deinit_all', c_uint),
]
gnutls_certificate_client_retrieve_function = CFUNCTYPE(c_int, gnutls_session_t, POINTER(gnutls_datum_t), c_int, POINTER(gnutls_pk_algorithm_t), c_int, POINTER(gnutls_retr_st))
gnutls_certificate_server_retrieve_function = CFUNCTYPE(c_int, gnutls_session_t, POINTER(gnutls_retr_st))
gnutls_sign_func = CFUNCTYPE(c_int, gnutls_session_t, c_void_p, gnutls_certificate_type_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t))
class gnutls_openpgp_keyring_int(Structure):
    pass
gnutls_openpgp_keyring_int._fields_ = [
]
gnutls_openpgp_keyring_t = POINTER(gnutls_openpgp_keyring_int)
gnutls_certificate_print_formats_t = gnutls_certificate_print_formats
gnutls_x509_dn_t = c_void_p
class gnutls_x509_ava_st(Structure):
    pass
gnutls_x509_ava_st._fields_ = [
    ('oid', gnutls_datum_t),
    ('value', gnutls_datum_t),
    ('value_tag', c_ulong),
]
class gnutls_pkcs7_int(Structure):
    pass
gnutls_pkcs7_int._fields_ = [
]
gnutls_pkcs7_t = POINTER(gnutls_pkcs7_int)
class gnutls_x509_crq_int(Structure):
    pass
gnutls_x509_crq_int._fields_ = [
]
gnutls_x509_crq_t = POINTER(gnutls_x509_crq_int)
__all__ = ['key', 'gnutls_transport_ptr_t', 'gnutls_session_int',
           'gnutls_srp_server_credentials_st',
           'gnutls_oprfi_callback_func', '__ssize_t',
           'gnutls_certificate_print_formats_t', 'gnutls_pkcs7_int',
           'gnutls_psk_client_credentials_st', 'gnutls_priority_t',
           'gnutls_certificate_credentials_st',
           'gnutls_psk_server_credentials_t', 'gnutls_x509_crt_t',
           'gnutls_psk_client_credentials_t', 'gnutls_x509_privkey_t',
           'gnutls_openpgp_keyring_t', 'gnutls_x509_privkey_int',
           'gnutls_push_func', 'gnutls_x509_crq_int',
           'gnutls_psk_server_credentials_st', 'gnutls_openpgp_crt_t',
           'gnutls_certificate_client_credentials', 'size_t',
           'gnutls_ia_avp_func', 'gnutls_params_st',
           'gnutls_anon_client_credentials_t', 'gnutls_dh_params_t',
           'gnutls_anon_client_credentials_st', 'gnutls_sign_func',
           'gnutls_srp_server_credentials_function', 'cert',
           'gnutls_x509_crt_int', 'gnutls_realloc_function',
           'gnutls_srp_client_credentials_function',
           'gnutls_ia_server_credentials_st',
           'gnutls_srp_client_credentials_st',
           'gnutls_calloc_function', 'gnutls_priority_st',
           'gnutls_x509_crl_int', 'params',
           'gnutls_certificate_server_credentials',
           'gnutls_handshake_post_client_hello_func',
           'gnutls_session_t',
           'gnutls_psk_client_credentials_function',
           'gnutls_openpgp_privkey_int', 'gnutls_retr_st',
           'gnutls_is_secure_function', 'gnutls_db_retr_func',
           'gnutls_openpgp_keyring_int',
           'gnutls_srp_client_credentials_t',
           'gnutls_openpgp_recv_key_func',
           'gnutls_anon_server_credentials_t', 'gnutls_dh_params_int',
           'gnutls_datum_t',
           'gnutls_certificate_server_retrieve_function',
           'gnutls_ia_server_credentials_t', 'gnutls_x509_ava_st',
           'gnutls_alloc_function',
           'gnutls_psk_server_credentials_function',
           'gnutls_anon_server_credentials_st',
           'gnutls_params_function',
           'gnutls_srp_server_credentials_t',
           'gnutls_openpgp_crt_int', 'gnutls_log_func',
           'gnutls_rsa_params_t', 'gnutls_openpgp_crt_fmt_t',
           'gnutls_x509_dn_t', 'gnutls_x509_crq_t',
           'gnutls_pull_func', 'gnutls_db_remove_func',
           'gnutls_ia_client_credentials_t',
           'gnutls_certificate_credentials_t', 'gnutls_pkcs7_t',
           'gnutls_ia_client_credentials_st', 'gnutls_db_store_func',
           'ssize_t', 'gnutls_openpgp_privkey_t',
           'gnutls_free_function', 'gnutls_x509_crl_t',
           'gnutls_certificate_client_retrieve_function']
