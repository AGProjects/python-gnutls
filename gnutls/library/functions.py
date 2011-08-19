# Copyright (C) 2007-2010 AG Projects. See LICENSE for details.
#

import sys
from ctypes import *

from gnutls.library import libgnutls, libgnutls_extra
from gnutls.library.types import *


# Functions
#

gnutls_alert_get = libgnutls.gnutls_alert_get
gnutls_alert_get.argtypes = [gnutls_session_t]
gnutls_alert_get.restype = gnutls_alert_description_t

gnutls_alert_get_name = libgnutls.gnutls_alert_get_name
gnutls_alert_get_name.argtypes = [gnutls_alert_description_t]
gnutls_alert_get_name.restype = c_char_p

gnutls_alert_send = libgnutls.gnutls_alert_send
gnutls_alert_send.argtypes = [gnutls_session_t, gnutls_alert_level_t, gnutls_alert_description_t]
gnutls_alert_send.restype = c_int

gnutls_alert_send_appropriate = libgnutls.gnutls_alert_send_appropriate
gnutls_alert_send_appropriate.argtypes = [gnutls_session_t, c_int]
gnutls_alert_send_appropriate.restype = c_int

gnutls_anon_allocate_client_credentials = libgnutls.gnutls_anon_allocate_client_credentials
gnutls_anon_allocate_client_credentials.argtypes = [POINTER(gnutls_anon_client_credentials_t)]
gnutls_anon_allocate_client_credentials.restype = c_int

gnutls_anon_allocate_server_credentials = libgnutls.gnutls_anon_allocate_server_credentials
gnutls_anon_allocate_server_credentials.argtypes = [POINTER(gnutls_anon_server_credentials_t)]
gnutls_anon_allocate_server_credentials.restype = c_int

gnutls_anon_free_client_credentials = libgnutls.gnutls_anon_free_client_credentials
gnutls_anon_free_client_credentials.argtypes = [gnutls_anon_client_credentials_t]
gnutls_anon_free_client_credentials.restype = None

gnutls_anon_free_server_credentials = libgnutls.gnutls_anon_free_server_credentials
gnutls_anon_free_server_credentials.argtypes = [gnutls_anon_server_credentials_t]
gnutls_anon_free_server_credentials.restype = None

gnutls_anon_set_params_function = libgnutls.gnutls_anon_set_params_function
gnutls_anon_set_params_function.argtypes = [gnutls_anon_server_credentials_t, gnutls_params_function]
gnutls_anon_set_params_function.restype = None

gnutls_anon_set_server_dh_params = libgnutls.gnutls_anon_set_server_dh_params
gnutls_anon_set_server_dh_params.argtypes = [gnutls_anon_server_credentials_t, gnutls_dh_params_t]
gnutls_anon_set_server_dh_params.restype = None

gnutls_anon_set_server_params_function = libgnutls.gnutls_anon_set_server_params_function
gnutls_anon_set_server_params_function.argtypes = [gnutls_anon_server_credentials_t, gnutls_params_function]
gnutls_anon_set_server_params_function.restype = None

gnutls_auth_client_get_type = libgnutls.gnutls_auth_client_get_type
gnutls_auth_client_get_type.argtypes = [gnutls_session_t]
gnutls_auth_client_get_type.restype = gnutls_credentials_type_t

gnutls_auth_get_type = libgnutls.gnutls_auth_get_type
gnutls_auth_get_type.argtypes = [gnutls_session_t]
gnutls_auth_get_type.restype = gnutls_credentials_type_t

gnutls_auth_server_get_type = libgnutls.gnutls_auth_server_get_type
gnutls_auth_server_get_type.argtypes = [gnutls_session_t]
gnutls_auth_server_get_type.restype = gnutls_credentials_type_t

gnutls_bye = libgnutls.gnutls_bye
gnutls_bye.argtypes = [gnutls_session_t, gnutls_close_request_t]
gnutls_bye.restype = c_int

gnutls_certificate_activation_time_peers = libgnutls.gnutls_certificate_activation_time_peers
gnutls_certificate_activation_time_peers.argtypes = [gnutls_session_t]
gnutls_certificate_activation_time_peers.restype = time_t
gnutls_certificate_activation_time_peers.errmsg = "cannot get certificate activation time"

gnutls_certificate_allocate_credentials = libgnutls.gnutls_certificate_allocate_credentials
gnutls_certificate_allocate_credentials.argtypes = [POINTER(gnutls_certificate_credentials_t)]
gnutls_certificate_allocate_credentials.restype = c_int

gnutls_certificate_client_get_request_status = libgnutls.gnutls_certificate_client_get_request_status
gnutls_certificate_client_get_request_status.argtypes = [gnutls_session_t]
gnutls_certificate_client_get_request_status.restype = c_int

gnutls_certificate_client_set_retrieve_function = libgnutls.gnutls_certificate_client_set_retrieve_function
gnutls_certificate_client_set_retrieve_function.argtypes = [gnutls_certificate_credentials_t, gnutls_certificate_client_retrieve_function]
gnutls_certificate_client_set_retrieve_function.restype = None

gnutls_certificate_expiration_time_peers = libgnutls.gnutls_certificate_expiration_time_peers
gnutls_certificate_expiration_time_peers.argtypes = [gnutls_session_t]
gnutls_certificate_expiration_time_peers.restype = time_t
gnutls_certificate_expiration_time_peers.errmsg = "cannot get certificate expiration time"

gnutls_certificate_free_ca_names = libgnutls.gnutls_certificate_free_ca_names
gnutls_certificate_free_ca_names.argtypes = [gnutls_certificate_credentials_t]
gnutls_certificate_free_ca_names.restype = None

gnutls_certificate_free_cas = libgnutls.gnutls_certificate_free_cas
gnutls_certificate_free_cas.argtypes = [gnutls_certificate_credentials_t]
gnutls_certificate_free_cas.restype = None

gnutls_certificate_free_credentials = libgnutls.gnutls_certificate_free_credentials
gnutls_certificate_free_credentials.argtypes = [gnutls_certificate_credentials_t]
gnutls_certificate_free_credentials.restype = None

gnutls_certificate_free_crls = libgnutls.gnutls_certificate_free_crls
gnutls_certificate_free_crls.argtypes = [gnutls_certificate_credentials_t]
gnutls_certificate_free_crls.restype = None

gnutls_certificate_free_keys = libgnutls.gnutls_certificate_free_keys
gnutls_certificate_free_keys.argtypes = [gnutls_certificate_credentials_t]
gnutls_certificate_free_keys.restype = None

gnutls_certificate_get_ours = libgnutls.gnutls_certificate_get_ours
gnutls_certificate_get_ours.argtypes = [gnutls_session_t]
gnutls_certificate_get_ours.restype = POINTER(gnutls_datum_t)

gnutls_certificate_get_peers = libgnutls.gnutls_certificate_get_peers
gnutls_certificate_get_peers.argtypes = [gnutls_session_t, POINTER(c_uint)]
gnutls_certificate_get_peers.restype = POINTER(gnutls_datum_t)

gnutls_certificate_get_x509_cas = libgnutls.gnutls_certificate_get_x509_cas
gnutls_certificate_get_x509_cas.argtypes = [gnutls_certificate_credentials_t, POINTER(POINTER(gnutls_x509_crt_t)), POINTER(c_uint)]
gnutls_certificate_get_x509_cas.restype = None

gnutls_certificate_get_x509_crls = libgnutls.gnutls_certificate_get_x509_crls
gnutls_certificate_get_x509_crls.argtypes = [gnutls_certificate_credentials_t, POINTER(POINTER(gnutls_x509_crl_t)), POINTER(c_uint)]
gnutls_certificate_get_x509_crls.restype = None

gnutls_certificate_send_x509_rdn_sequence = libgnutls.gnutls_certificate_send_x509_rdn_sequence
gnutls_certificate_send_x509_rdn_sequence.argtypes = [gnutls_session_t, c_int]
gnutls_certificate_send_x509_rdn_sequence.restype = None

gnutls_certificate_server_set_request = libgnutls.gnutls_certificate_server_set_request
gnutls_certificate_server_set_request.argtypes = [gnutls_session_t, gnutls_certificate_request_t]
gnutls_certificate_server_set_request.restype = None

gnutls_certificate_server_set_retrieve_function = libgnutls.gnutls_certificate_server_set_retrieve_function
gnutls_certificate_server_set_retrieve_function.argtypes = [gnutls_certificate_credentials_t, gnutls_certificate_server_retrieve_function]
gnutls_certificate_server_set_retrieve_function.restype = None

gnutls_certificate_set_dh_params = libgnutls.gnutls_certificate_set_dh_params
gnutls_certificate_set_dh_params.argtypes = [gnutls_certificate_credentials_t, gnutls_dh_params_t]
gnutls_certificate_set_dh_params.restype = None

gnutls_certificate_set_params_function = libgnutls.gnutls_certificate_set_params_function
gnutls_certificate_set_params_function.argtypes = [gnutls_certificate_credentials_t, gnutls_params_function]
gnutls_certificate_set_params_function.restype = None

gnutls_certificate_set_rsa_export_params = libgnutls.gnutls_certificate_set_rsa_export_params
gnutls_certificate_set_rsa_export_params.argtypes = [gnutls_certificate_credentials_t, gnutls_rsa_params_t]
gnutls_certificate_set_rsa_export_params.restype = None

gnutls_certificate_set_verify_flags = libgnutls.gnutls_certificate_set_verify_flags
gnutls_certificate_set_verify_flags.argtypes = [gnutls_certificate_credentials_t, c_uint]
gnutls_certificate_set_verify_flags.restype = None

gnutls_certificate_set_verify_limits = libgnutls.gnutls_certificate_set_verify_limits
gnutls_certificate_set_verify_limits.argtypes = [gnutls_certificate_credentials_t, c_uint, c_uint]
gnutls_certificate_set_verify_limits.restype = None

gnutls_certificate_set_x509_crl = libgnutls.gnutls_certificate_set_x509_crl
gnutls_certificate_set_x509_crl.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_x509_crl_t), c_int]
gnutls_certificate_set_x509_crl.restype = c_int

gnutls_certificate_set_x509_crl_file = libgnutls.gnutls_certificate_set_x509_crl_file
gnutls_certificate_set_x509_crl_file.argtypes = [gnutls_certificate_credentials_t, c_char_p, gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_crl_file.restype = c_int

gnutls_certificate_set_x509_crl_mem = libgnutls.gnutls_certificate_set_x509_crl_mem
gnutls_certificate_set_x509_crl_mem.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_crl_mem.restype = c_int

gnutls_certificate_set_x509_key = libgnutls.gnutls_certificate_set_x509_key
gnutls_certificate_set_x509_key.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_x509_crt_t), c_int, gnutls_x509_privkey_t]
gnutls_certificate_set_x509_key.restype = c_int

gnutls_certificate_set_x509_key_file = libgnutls.gnutls_certificate_set_x509_key_file
gnutls_certificate_set_x509_key_file.argtypes = [gnutls_certificate_credentials_t, c_char_p, c_char_p, gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_key_file.restype = c_int

gnutls_certificate_set_x509_key_mem = libgnutls.gnutls_certificate_set_x509_key_mem
gnutls_certificate_set_x509_key_mem.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_key_mem.restype = c_int

gnutls_certificate_set_x509_simple_pkcs12_file = libgnutls.gnutls_certificate_set_x509_simple_pkcs12_file
gnutls_certificate_set_x509_simple_pkcs12_file.argtypes = [gnutls_certificate_credentials_t, c_char_p, gnutls_x509_crt_fmt_t, c_char_p]
gnutls_certificate_set_x509_simple_pkcs12_file.restype = c_int

gnutls_certificate_set_x509_trust = libgnutls.gnutls_certificate_set_x509_trust
gnutls_certificate_set_x509_trust.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_x509_crt_t), c_int]
gnutls_certificate_set_x509_trust.restype = c_int

gnutls_certificate_set_x509_trust_file = libgnutls.gnutls_certificate_set_x509_trust_file
gnutls_certificate_set_x509_trust_file.argtypes = [gnutls_certificate_credentials_t, c_char_p, gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_trust_file.restype = c_int

gnutls_certificate_set_x509_trust_mem = libgnutls.gnutls_certificate_set_x509_trust_mem
gnutls_certificate_set_x509_trust_mem.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_trust_mem.restype = c_int

gnutls_certificate_type_get = libgnutls.gnutls_certificate_type_get
gnutls_certificate_type_get.argtypes = [gnutls_session_t]
gnutls_certificate_type_get.restype = gnutls_certificate_type_t

gnutls_certificate_type_get_id = libgnutls.gnutls_certificate_type_get_id
gnutls_certificate_type_get_id.argtypes = [c_char_p]
gnutls_certificate_type_get_id.restype = gnutls_certificate_type_t

gnutls_certificate_type_get_name = libgnutls.gnutls_certificate_type_get_name
gnutls_certificate_type_get_name.argtypes = [gnutls_certificate_type_t]
gnutls_certificate_type_get_name.restype = c_char_p

gnutls_certificate_type_list = libgnutls.gnutls_certificate_type_list
gnutls_certificate_type_list.argtypes = []
gnutls_certificate_type_list.restype = POINTER(gnutls_certificate_type_t)

gnutls_certificate_type_set_priority = libgnutls.gnutls_certificate_type_set_priority
gnutls_certificate_type_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_certificate_type_set_priority.restype = c_int

gnutls_certificate_verify_peers = libgnutls.gnutls_certificate_verify_peers
gnutls_certificate_verify_peers.argtypes = [gnutls_session_t]
gnutls_certificate_verify_peers.restype = c_int

gnutls_certificate_verify_peers2 = libgnutls.gnutls_certificate_verify_peers2
gnutls_certificate_verify_peers2.argtypes = [gnutls_session_t, POINTER(c_uint)]
gnutls_certificate_verify_peers2.restype = c_int

gnutls_check_version = libgnutls.gnutls_check_version
gnutls_check_version.argtypes = [c_char_p]
gnutls_check_version.restype = c_char_p

gnutls_cipher_get = libgnutls.gnutls_cipher_get
gnutls_cipher_get.argtypes = [gnutls_session_t]
gnutls_cipher_get.restype = gnutls_cipher_algorithm_t

gnutls_cipher_get_id = libgnutls.gnutls_cipher_get_id
gnutls_cipher_get_id.argtypes = [c_char_p]
gnutls_cipher_get_id.restype = gnutls_cipher_algorithm_t

gnutls_cipher_get_key_size = libgnutls.gnutls_cipher_get_key_size
gnutls_cipher_get_key_size.argtypes = [gnutls_cipher_algorithm_t]
gnutls_cipher_get_key_size.restype = size_t

gnutls_cipher_get_name = libgnutls.gnutls_cipher_get_name
gnutls_cipher_get_name.argtypes = [gnutls_cipher_algorithm_t]
gnutls_cipher_get_name.restype = c_char_p

gnutls_cipher_list = libgnutls.gnutls_cipher_list
gnutls_cipher_list.argtypes = []
gnutls_cipher_list.restype = POINTER(gnutls_cipher_algorithm_t)

gnutls_cipher_set_priority = libgnutls.gnutls_cipher_set_priority
gnutls_cipher_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_cipher_set_priority.restype = c_int

gnutls_cipher_suite_get_name = libgnutls.gnutls_cipher_suite_get_name
gnutls_cipher_suite_get_name.argtypes = [gnutls_kx_algorithm_t, gnutls_cipher_algorithm_t, gnutls_mac_algorithm_t]
gnutls_cipher_suite_get_name.restype = c_char_p

gnutls_cipher_suite_info = libgnutls.gnutls_cipher_suite_info
gnutls_cipher_suite_info.argtypes = [size_t, c_char_p, POINTER(gnutls_kx_algorithm_t), POINTER(gnutls_cipher_algorithm_t), POINTER(gnutls_mac_algorithm_t), POINTER(gnutls_protocol_t)]
gnutls_cipher_suite_info.restype = c_char_p

gnutls_compression_get = libgnutls.gnutls_compression_get
gnutls_compression_get.argtypes = [gnutls_session_t]
gnutls_compression_get.restype = gnutls_compression_method_t

gnutls_compression_get_id = libgnutls.gnutls_compression_get_id
gnutls_compression_get_id.argtypes = [c_char_p]
gnutls_compression_get_id.restype = gnutls_compression_method_t

gnutls_compression_get_name = libgnutls.gnutls_compression_get_name
gnutls_compression_get_name.argtypes = [gnutls_compression_method_t]
gnutls_compression_get_name.restype = c_char_p

gnutls_compression_list = libgnutls.gnutls_compression_list
gnutls_compression_list.argtypes = []
gnutls_compression_list.restype = POINTER(gnutls_compression_method_t)

gnutls_compression_set_priority = libgnutls.gnutls_compression_set_priority
gnutls_compression_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_compression_set_priority.restype = c_int

gnutls_credentials_clear = libgnutls.gnutls_credentials_clear
gnutls_credentials_clear.argtypes = [gnutls_session_t]
gnutls_credentials_clear.restype = None

gnutls_credentials_set = libgnutls.gnutls_credentials_set
gnutls_credentials_set.argtypes = [gnutls_session_t, gnutls_credentials_type_t, c_void_p]
gnutls_credentials_set.restype = c_int

gnutls_db_check_entry = libgnutls.gnutls_db_check_entry
gnutls_db_check_entry.argtypes = [gnutls_session_t, gnutls_datum_t]
gnutls_db_check_entry.restype = c_int

gnutls_db_get_ptr = libgnutls.gnutls_db_get_ptr
gnutls_db_get_ptr.argtypes = [gnutls_session_t]
gnutls_db_get_ptr.restype = c_void_p

gnutls_db_remove_session = libgnutls.gnutls_db_remove_session
gnutls_db_remove_session.argtypes = [gnutls_session_t]
gnutls_db_remove_session.restype = None

gnutls_db_set_cache_expiration = libgnutls.gnutls_db_set_cache_expiration
gnutls_db_set_cache_expiration.argtypes = [gnutls_session_t, c_int]
gnutls_db_set_cache_expiration.restype = None

gnutls_db_set_ptr = libgnutls.gnutls_db_set_ptr
gnutls_db_set_ptr.argtypes = [gnutls_session_t, c_void_p]
gnutls_db_set_ptr.restype = None

gnutls_db_set_remove_function = libgnutls.gnutls_db_set_remove_function
gnutls_db_set_remove_function.argtypes = [gnutls_session_t, gnutls_db_remove_func]
gnutls_db_set_remove_function.restype = None

gnutls_db_set_retrieve_function = libgnutls.gnutls_db_set_retrieve_function
gnutls_db_set_retrieve_function.argtypes = [gnutls_session_t, gnutls_db_retr_func]
gnutls_db_set_retrieve_function.restype = None

gnutls_db_set_store_function = libgnutls.gnutls_db_set_store_function
gnutls_db_set_store_function.argtypes = [gnutls_session_t, gnutls_db_store_func]
gnutls_db_set_store_function.restype = None

gnutls_deinit = libgnutls.gnutls_deinit
gnutls_deinit.argtypes = [gnutls_session_t]
gnutls_deinit.restype = None

gnutls_dh_get_group = libgnutls.gnutls_dh_get_group
gnutls_dh_get_group.argtypes = [gnutls_session_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_dh_get_group.restype = c_int

gnutls_dh_get_peers_public_bits = libgnutls.gnutls_dh_get_peers_public_bits
gnutls_dh_get_peers_public_bits.argtypes = [gnutls_session_t]
gnutls_dh_get_peers_public_bits.restype = c_int

gnutls_dh_get_prime_bits = libgnutls.gnutls_dh_get_prime_bits
gnutls_dh_get_prime_bits.argtypes = [gnutls_session_t]
gnutls_dh_get_prime_bits.restype = c_int

gnutls_dh_get_pubkey = libgnutls.gnutls_dh_get_pubkey
gnutls_dh_get_pubkey.argtypes = [gnutls_session_t, POINTER(gnutls_datum_t)]
gnutls_dh_get_pubkey.restype = c_int

gnutls_dh_get_secret_bits = libgnutls.gnutls_dh_get_secret_bits
gnutls_dh_get_secret_bits.argtypes = [gnutls_session_t]
gnutls_dh_get_secret_bits.restype = c_int

gnutls_dh_params_cpy = libgnutls.gnutls_dh_params_cpy
gnutls_dh_params_cpy.argtypes = [gnutls_dh_params_t, gnutls_dh_params_t]
gnutls_dh_params_cpy.restype = c_int

gnutls_dh_params_deinit = libgnutls.gnutls_dh_params_deinit
gnutls_dh_params_deinit.argtypes = [gnutls_dh_params_t]
gnutls_dh_params_deinit.restype = None

gnutls_dh_params_export_pkcs3 = libgnutls.gnutls_dh_params_export_pkcs3
gnutls_dh_params_export_pkcs3.argtypes = [gnutls_dh_params_t, gnutls_x509_crt_fmt_t, POINTER(c_ubyte), POINTER(size_t)]
gnutls_dh_params_export_pkcs3.restype = c_int

gnutls_dh_params_export_raw = libgnutls.gnutls_dh_params_export_raw
gnutls_dh_params_export_raw.argtypes = [gnutls_dh_params_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(c_uint)]
gnutls_dh_params_export_raw.restype = c_int

gnutls_dh_params_generate2 = libgnutls.gnutls_dh_params_generate2
gnutls_dh_params_generate2.argtypes = [gnutls_dh_params_t, c_uint]
gnutls_dh_params_generate2.restype = c_int

gnutls_dh_params_import_pkcs3 = libgnutls.gnutls_dh_params_import_pkcs3
gnutls_dh_params_import_pkcs3.argtypes = [gnutls_dh_params_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_dh_params_import_pkcs3.restype = c_int

gnutls_dh_params_import_raw = libgnutls.gnutls_dh_params_import_raw
gnutls_dh_params_import_raw.argtypes = [gnutls_dh_params_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_dh_params_import_raw.restype = c_int

gnutls_dh_params_init = libgnutls.gnutls_dh_params_init
gnutls_dh_params_init.argtypes = [POINTER(gnutls_dh_params_t)]
gnutls_dh_params_init.restype = c_int

gnutls_dh_set_prime_bits = libgnutls.gnutls_dh_set_prime_bits
gnutls_dh_set_prime_bits.argtypes = [gnutls_session_t, c_uint]
gnutls_dh_set_prime_bits.restype = None

gnutls_error_is_fatal = libgnutls.gnutls_error_is_fatal
gnutls_error_is_fatal.argtypes = [c_int]
gnutls_error_is_fatal.restype = c_int

gnutls_error_to_alert = libgnutls.gnutls_error_to_alert
gnutls_error_to_alert.argtypes = [c_int, POINTER(c_int)]
gnutls_error_to_alert.restype = c_int

gnutls_extra_check_version = libgnutls_extra.gnutls_extra_check_version
gnutls_extra_check_version.argtypes = [c_char_p]
gnutls_extra_check_version.restype = c_char_p

gnutls_fingerprint = libgnutls.gnutls_fingerprint
gnutls_fingerprint.argtypes = [gnutls_digest_algorithm_t, POINTER(gnutls_datum_t), c_void_p, POINTER(size_t)]
gnutls_fingerprint.restype = c_int

gnutls_global_deinit = libgnutls.gnutls_global_deinit
gnutls_global_deinit.argtypes = []
gnutls_global_deinit.restype = None

gnutls_global_init = libgnutls.gnutls_global_init
gnutls_global_init.argtypes = []
gnutls_global_init.restype = c_int

gnutls_global_init_extra = libgnutls_extra.gnutls_global_init_extra
gnutls_global_init_extra.argtypes = []
gnutls_global_init_extra.restype = c_int

gnutls_global_set_log_function = libgnutls.gnutls_global_set_log_function
gnutls_global_set_log_function.argtypes = [gnutls_log_func]
gnutls_global_set_log_function.restype = None

gnutls_global_set_log_level = libgnutls.gnutls_global_set_log_level
gnutls_global_set_log_level.argtypes = [c_int]
gnutls_global_set_log_level.restype = None

gnutls_global_set_mem_functions = libgnutls.gnutls_global_set_mem_functions
gnutls_global_set_mem_functions.argtypes = [gnutls_alloc_function, gnutls_alloc_function, gnutls_is_secure_function, gnutls_realloc_function, gnutls_free_function]
gnutls_global_set_mem_functions.restype = None

gnutls_handshake = libgnutls.gnutls_handshake
gnutls_handshake.argtypes = [gnutls_session_t]
gnutls_handshake.restype = c_int

gnutls_handshake_get_last_in = libgnutls.gnutls_handshake_get_last_in
gnutls_handshake_get_last_in.argtypes = [gnutls_session_t]
gnutls_handshake_get_last_in.restype = gnutls_handshake_description_t

gnutls_handshake_get_last_out = libgnutls.gnutls_handshake_get_last_out
gnutls_handshake_get_last_out.argtypes = [gnutls_session_t]
gnutls_handshake_get_last_out.restype = gnutls_handshake_description_t

gnutls_handshake_set_max_packet_length = libgnutls.gnutls_handshake_set_max_packet_length
gnutls_handshake_set_max_packet_length.argtypes = [gnutls_session_t, size_t]
gnutls_handshake_set_max_packet_length.restype = None

gnutls_handshake_set_post_client_hello_function = libgnutls.gnutls_handshake_set_post_client_hello_function
gnutls_handshake_set_post_client_hello_function.argtypes = [gnutls_session_t, gnutls_handshake_post_client_hello_func]
gnutls_handshake_set_post_client_hello_function.restype = None

gnutls_handshake_set_private_extensions = libgnutls.gnutls_handshake_set_private_extensions
gnutls_handshake_set_private_extensions.argtypes = [gnutls_session_t, c_int]
gnutls_handshake_set_private_extensions.restype = None

gnutls_hex2bin = libgnutls.gnutls_hex2bin
gnutls_hex2bin.argtypes = [c_char_p, size_t, c_char_p, POINTER(size_t)]
gnutls_hex2bin.restype = c_int

gnutls_hex_decode = libgnutls.gnutls_hex_decode
gnutls_hex_decode.argtypes = [POINTER(gnutls_datum_t), c_char_p, POINTER(size_t)]
gnutls_hex_decode.restype = c_int

gnutls_hex_encode = libgnutls.gnutls_hex_encode
gnutls_hex_encode.argtypes = [POINTER(gnutls_datum_t), c_char_p, POINTER(size_t)]
gnutls_hex_encode.restype = c_int

gnutls_ia_allocate_client_credentials = libgnutls_extra.gnutls_ia_allocate_client_credentials
gnutls_ia_allocate_client_credentials.argtypes = [POINTER(gnutls_ia_client_credentials_t)]
gnutls_ia_allocate_client_credentials.restype = c_int

gnutls_ia_allocate_server_credentials = libgnutls_extra.gnutls_ia_allocate_server_credentials
gnutls_ia_allocate_server_credentials.argtypes = [POINTER(gnutls_ia_server_credentials_t)]
gnutls_ia_allocate_server_credentials.restype = c_int

gnutls_ia_enable = libgnutls_extra.gnutls_ia_enable
gnutls_ia_enable.argtypes = [gnutls_session_t, c_int]
gnutls_ia_enable.restype = None

gnutls_ia_endphase_send = libgnutls_extra.gnutls_ia_endphase_send
gnutls_ia_endphase_send.argtypes = [gnutls_session_t, c_int]
gnutls_ia_endphase_send.restype = c_int

gnutls_ia_extract_inner_secret = libgnutls_extra.gnutls_ia_extract_inner_secret
gnutls_ia_extract_inner_secret.argtypes = [gnutls_session_t, c_char_p]
gnutls_ia_extract_inner_secret.restype = None

gnutls_ia_free_client_credentials = libgnutls_extra.gnutls_ia_free_client_credentials
gnutls_ia_free_client_credentials.argtypes = [gnutls_ia_client_credentials_t]
gnutls_ia_free_client_credentials.restype = None

gnutls_ia_free_server_credentials = libgnutls_extra.gnutls_ia_free_server_credentials
gnutls_ia_free_server_credentials.argtypes = [gnutls_ia_server_credentials_t]
gnutls_ia_free_server_credentials.restype = None

gnutls_ia_generate_challenge = libgnutls_extra.gnutls_ia_generate_challenge
gnutls_ia_generate_challenge.argtypes = [gnutls_session_t, size_t, c_char_p]
gnutls_ia_generate_challenge.restype = c_int

gnutls_ia_get_client_avp_ptr = libgnutls_extra.gnutls_ia_get_client_avp_ptr
gnutls_ia_get_client_avp_ptr.argtypes = [gnutls_ia_client_credentials_t]
gnutls_ia_get_client_avp_ptr.restype = c_void_p

gnutls_ia_get_server_avp_ptr = libgnutls_extra.gnutls_ia_get_server_avp_ptr
gnutls_ia_get_server_avp_ptr.argtypes = [gnutls_ia_server_credentials_t]
gnutls_ia_get_server_avp_ptr.restype = c_void_p

gnutls_ia_handshake = libgnutls_extra.gnutls_ia_handshake
gnutls_ia_handshake.argtypes = [gnutls_session_t]
gnutls_ia_handshake.restype = c_int

gnutls_ia_handshake_p = libgnutls_extra.gnutls_ia_handshake_p
gnutls_ia_handshake_p.argtypes = [gnutls_session_t]
gnutls_ia_handshake_p.restype = c_int

gnutls_ia_permute_inner_secret = libgnutls_extra.gnutls_ia_permute_inner_secret
gnutls_ia_permute_inner_secret.argtypes = [gnutls_session_t, size_t, c_char_p]
gnutls_ia_permute_inner_secret.restype = c_int

gnutls_ia_recv = libgnutls_extra.gnutls_ia_recv
gnutls_ia_recv.argtypes = [gnutls_session_t, c_char_p, size_t]
gnutls_ia_recv.restype = ssize_t

gnutls_ia_send = libgnutls_extra.gnutls_ia_send
gnutls_ia_send.argtypes = [gnutls_session_t, c_char_p, size_t]
gnutls_ia_send.restype = ssize_t

gnutls_ia_set_client_avp_function = libgnutls_extra.gnutls_ia_set_client_avp_function
gnutls_ia_set_client_avp_function.argtypes = [gnutls_ia_client_credentials_t, gnutls_ia_avp_func]
gnutls_ia_set_client_avp_function.restype = None

gnutls_ia_set_client_avp_ptr = libgnutls_extra.gnutls_ia_set_client_avp_ptr
gnutls_ia_set_client_avp_ptr.argtypes = [gnutls_ia_client_credentials_t, c_void_p]
gnutls_ia_set_client_avp_ptr.restype = None

gnutls_ia_set_server_avp_function = libgnutls_extra.gnutls_ia_set_server_avp_function
gnutls_ia_set_server_avp_function.argtypes = [gnutls_ia_server_credentials_t, gnutls_ia_avp_func]
gnutls_ia_set_server_avp_function.restype = None

gnutls_ia_set_server_avp_ptr = libgnutls_extra.gnutls_ia_set_server_avp_ptr
gnutls_ia_set_server_avp_ptr.argtypes = [gnutls_ia_server_credentials_t, c_void_p]
gnutls_ia_set_server_avp_ptr.restype = None

gnutls_ia_verify_endphase = libgnutls_extra.gnutls_ia_verify_endphase
gnutls_ia_verify_endphase.argtypes = [gnutls_session_t, c_char_p]
gnutls_ia_verify_endphase.restype = c_int

gnutls_init = libgnutls.gnutls_init
gnutls_init.argtypes = [POINTER(gnutls_session_t), gnutls_connection_end_t]
gnutls_init.restype = c_int

gnutls_kx_get = libgnutls.gnutls_kx_get
gnutls_kx_get.argtypes = [gnutls_session_t]
gnutls_kx_get.restype = gnutls_kx_algorithm_t

gnutls_kx_get_id = libgnutls.gnutls_kx_get_id
gnutls_kx_get_id.argtypes = [c_char_p]
gnutls_kx_get_id.restype = gnutls_kx_algorithm_t

gnutls_kx_get_name = libgnutls.gnutls_kx_get_name
gnutls_kx_get_name.argtypes = [gnutls_kx_algorithm_t]
gnutls_kx_get_name.restype = c_char_p

gnutls_kx_list = libgnutls.gnutls_kx_list
gnutls_kx_list.argtypes = []
gnutls_kx_list.restype = POINTER(gnutls_kx_algorithm_t)

gnutls_kx_set_priority = libgnutls.gnutls_kx_set_priority
gnutls_kx_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_kx_set_priority.restype = c_int

gnutls_mac_get = libgnutls.gnutls_mac_get
gnutls_mac_get.argtypes = [gnutls_session_t]
gnutls_mac_get.restype = gnutls_mac_algorithm_t

gnutls_mac_get_id = libgnutls.gnutls_mac_get_id
gnutls_mac_get_id.argtypes = [c_char_p]
gnutls_mac_get_id.restype = gnutls_mac_algorithm_t

gnutls_mac_get_key_size = libgnutls.gnutls_mac_get_key_size
gnutls_mac_get_key_size.argtypes = [gnutls_mac_algorithm_t]
gnutls_mac_get_key_size.restype = size_t

gnutls_mac_get_name = libgnutls.gnutls_mac_get_name
gnutls_mac_get_name.argtypes = [gnutls_mac_algorithm_t]
gnutls_mac_get_name.restype = c_char_p

gnutls_mac_list = libgnutls.gnutls_mac_list
gnutls_mac_list.argtypes = []
gnutls_mac_list.restype = POINTER(gnutls_mac_algorithm_t)

gnutls_mac_set_priority = libgnutls.gnutls_mac_set_priority
gnutls_mac_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_mac_set_priority.restype = c_int

gnutls_pem_base64_decode = libgnutls.gnutls_pem_base64_decode
gnutls_pem_base64_decode.argtypes = [c_char_p, POINTER(gnutls_datum_t), POINTER(c_ubyte), POINTER(size_t)]
gnutls_pem_base64_decode.restype = c_int

gnutls_pem_base64_decode_alloc = libgnutls.gnutls_pem_base64_decode_alloc
gnutls_pem_base64_decode_alloc.argtypes = [c_char_p, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_pem_base64_decode_alloc.restype = c_int

gnutls_pem_base64_encode = libgnutls.gnutls_pem_base64_encode
gnutls_pem_base64_encode.argtypes = [c_char_p, POINTER(gnutls_datum_t), c_char_p, POINTER(size_t)]
gnutls_pem_base64_encode.restype = c_int

gnutls_pem_base64_encode_alloc = libgnutls.gnutls_pem_base64_encode_alloc
gnutls_pem_base64_encode_alloc.argtypes = [c_char_p, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_pem_base64_encode_alloc.restype = c_int

gnutls_perror = libgnutls.gnutls_perror
gnutls_perror.argtypes = [c_int]
gnutls_perror.restype = None

gnutls_pk_algorithm_get_name = libgnutls.gnutls_pk_algorithm_get_name
gnutls_pk_algorithm_get_name.argtypes = [gnutls_pk_algorithm_t]
gnutls_pk_algorithm_get_name.restype = c_char_p

gnutls_pkcs7_deinit = libgnutls.gnutls_pkcs7_deinit
gnutls_pkcs7_deinit.argtypes = [gnutls_pkcs7_t]
gnutls_pkcs7_deinit.restype = None

gnutls_pkcs7_delete_crl = libgnutls.gnutls_pkcs7_delete_crl
gnutls_pkcs7_delete_crl.argtypes = [gnutls_pkcs7_t, c_int]
gnutls_pkcs7_delete_crl.restype = c_int

gnutls_pkcs7_delete_crt = libgnutls.gnutls_pkcs7_delete_crt
gnutls_pkcs7_delete_crt.argtypes = [gnutls_pkcs7_t, c_int]
gnutls_pkcs7_delete_crt.restype = c_int

gnutls_pkcs7_export = libgnutls.gnutls_pkcs7_export
gnutls_pkcs7_export.argtypes = [gnutls_pkcs7_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_pkcs7_export.restype = c_int

gnutls_pkcs7_get_crl_count = libgnutls.gnutls_pkcs7_get_crl_count
gnutls_pkcs7_get_crl_count.argtypes = [gnutls_pkcs7_t]
gnutls_pkcs7_get_crl_count.restype = c_int

gnutls_pkcs7_get_crl_raw = libgnutls.gnutls_pkcs7_get_crl_raw
gnutls_pkcs7_get_crl_raw.argtypes = [gnutls_pkcs7_t, c_int, c_void_p, POINTER(size_t)]
gnutls_pkcs7_get_crl_raw.restype = c_int

gnutls_pkcs7_get_crt_count = libgnutls.gnutls_pkcs7_get_crt_count
gnutls_pkcs7_get_crt_count.argtypes = [gnutls_pkcs7_t]
gnutls_pkcs7_get_crt_count.restype = c_int

gnutls_pkcs7_get_crt_raw = libgnutls.gnutls_pkcs7_get_crt_raw
gnutls_pkcs7_get_crt_raw.argtypes = [gnutls_pkcs7_t, c_int, c_void_p, POINTER(size_t)]
gnutls_pkcs7_get_crt_raw.restype = c_int

gnutls_pkcs7_import = libgnutls.gnutls_pkcs7_import
gnutls_pkcs7_import.argtypes = [gnutls_pkcs7_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_pkcs7_import.restype = c_int

gnutls_pkcs7_init = libgnutls.gnutls_pkcs7_init
gnutls_pkcs7_init.argtypes = [POINTER(gnutls_pkcs7_t)]
gnutls_pkcs7_init.restype = c_int

gnutls_pkcs7_set_crl = libgnutls.gnutls_pkcs7_set_crl
gnutls_pkcs7_set_crl.argtypes = [gnutls_pkcs7_t, gnutls_x509_crl_t]
gnutls_pkcs7_set_crl.restype = c_int

gnutls_pkcs7_set_crl_raw = libgnutls.gnutls_pkcs7_set_crl_raw
gnutls_pkcs7_set_crl_raw.argtypes = [gnutls_pkcs7_t, POINTER(gnutls_datum_t)]
gnutls_pkcs7_set_crl_raw.restype = c_int

gnutls_pkcs7_set_crt = libgnutls.gnutls_pkcs7_set_crt
gnutls_pkcs7_set_crt.argtypes = [gnutls_pkcs7_t, gnutls_x509_crt_t]
gnutls_pkcs7_set_crt.restype = c_int

gnutls_pkcs7_set_crt_raw = libgnutls.gnutls_pkcs7_set_crt_raw
gnutls_pkcs7_set_crt_raw.argtypes = [gnutls_pkcs7_t, POINTER(gnutls_datum_t)]
gnutls_pkcs7_set_crt_raw.restype = c_int

gnutls_prf = libgnutls.gnutls_prf
gnutls_prf.argtypes = [gnutls_session_t, size_t, c_char_p, c_int, size_t, c_char_p, size_t, c_char_p]
gnutls_prf.restype = c_int

gnutls_prf_raw = libgnutls.gnutls_prf_raw
gnutls_prf_raw.argtypes = [gnutls_session_t, size_t, c_char_p, size_t, c_char_p, size_t, c_char_p]
gnutls_prf_raw.restype = c_int

gnutls_priority_deinit = libgnutls.gnutls_priority_deinit
gnutls_priority_deinit.argtypes = [gnutls_priority_t]
gnutls_priority_deinit.restype = None

gnutls_priority_init = libgnutls.gnutls_priority_init
gnutls_priority_init.argtypes = [POINTER(gnutls_priority_t), c_char_p, POINTER(c_char_p)]
gnutls_priority_init.restype = c_int

gnutls_priority_set = libgnutls.gnutls_priority_set
gnutls_priority_set.argtypes = [gnutls_session_t, gnutls_priority_t]
gnutls_priority_set.restype = c_int

gnutls_priority_set_direct = libgnutls.gnutls_priority_set_direct
gnutls_priority_set_direct.argtypes = [gnutls_session_t, c_char_p, POINTER(c_char_p)]
gnutls_priority_set_direct.restype = c_int

gnutls_protocol_get_id = libgnutls.gnutls_protocol_get_id
gnutls_protocol_get_id.argtypes = [c_char_p]
gnutls_protocol_get_id.restype = gnutls_protocol_t

gnutls_protocol_get_name = libgnutls.gnutls_protocol_get_name
gnutls_protocol_get_name.argtypes = [gnutls_protocol_t]
gnutls_protocol_get_name.restype = c_char_p

gnutls_protocol_get_version = libgnutls.gnutls_protocol_get_version
gnutls_protocol_get_version.argtypes = [gnutls_session_t]
gnutls_protocol_get_version.restype = gnutls_protocol_t

gnutls_protocol_list = libgnutls.gnutls_protocol_list
gnutls_protocol_list.argtypes = []
gnutls_protocol_list.restype = POINTER(gnutls_protocol_t)

gnutls_protocol_set_priority = libgnutls.gnutls_protocol_set_priority
gnutls_protocol_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_protocol_set_priority.restype = c_int

gnutls_psk_allocate_client_credentials = libgnutls.gnutls_psk_allocate_client_credentials
gnutls_psk_allocate_client_credentials.argtypes = [POINTER(gnutls_psk_client_credentials_t)]
gnutls_psk_allocate_client_credentials.restype = c_int

gnutls_psk_allocate_server_credentials = libgnutls.gnutls_psk_allocate_server_credentials
gnutls_psk_allocate_server_credentials.argtypes = [POINTER(gnutls_psk_server_credentials_t)]
gnutls_psk_allocate_server_credentials.restype = c_int

gnutls_psk_client_get_hint = libgnutls.gnutls_psk_client_get_hint
gnutls_psk_client_get_hint.argtypes = [gnutls_session_t]
gnutls_psk_client_get_hint.restype = c_char_p

gnutls_psk_free_client_credentials = libgnutls.gnutls_psk_free_client_credentials
gnutls_psk_free_client_credentials.argtypes = [gnutls_psk_client_credentials_t]
gnutls_psk_free_client_credentials.restype = None

gnutls_psk_free_server_credentials = libgnutls.gnutls_psk_free_server_credentials
gnutls_psk_free_server_credentials.argtypes = [gnutls_psk_server_credentials_t]
gnutls_psk_free_server_credentials.restype = None

gnutls_psk_netconf_derive_key = libgnutls.gnutls_psk_netconf_derive_key
gnutls_psk_netconf_derive_key.argtypes = [c_char_p, c_char_p, c_char_p, POINTER(gnutls_datum_t)]
gnutls_psk_netconf_derive_key.restype = c_int

gnutls_psk_server_get_username = libgnutls.gnutls_psk_server_get_username
gnutls_psk_server_get_username.argtypes = [gnutls_session_t]
gnutls_psk_server_get_username.restype = c_char_p

gnutls_psk_set_client_credentials = libgnutls.gnutls_psk_set_client_credentials
gnutls_psk_set_client_credentials.argtypes = [gnutls_psk_client_credentials_t, c_char_p, POINTER(gnutls_datum_t), gnutls_psk_key_flags]
gnutls_psk_set_client_credentials.restype = c_int

gnutls_psk_set_client_credentials_function = libgnutls.gnutls_psk_set_client_credentials_function
gnutls_psk_set_client_credentials_function.argtypes = [gnutls_psk_client_credentials_t, gnutls_psk_client_credentials_function]
gnutls_psk_set_client_credentials_function.restype = None

gnutls_psk_set_params_function = libgnutls.gnutls_psk_set_params_function
gnutls_psk_set_params_function.argtypes = [gnutls_psk_server_credentials_t, gnutls_params_function]
gnutls_psk_set_params_function.restype = None

gnutls_psk_set_server_credentials_file = libgnutls.gnutls_psk_set_server_credentials_file
gnutls_psk_set_server_credentials_file.argtypes = [gnutls_psk_server_credentials_t, c_char_p]
gnutls_psk_set_server_credentials_file.restype = c_int

gnutls_psk_set_server_credentials_function = libgnutls.gnutls_psk_set_server_credentials_function
gnutls_psk_set_server_credentials_function.argtypes = [gnutls_psk_server_credentials_t, gnutls_psk_server_credentials_function]
gnutls_psk_set_server_credentials_function.restype = None

gnutls_psk_set_server_credentials_hint = libgnutls.gnutls_psk_set_server_credentials_hint
gnutls_psk_set_server_credentials_hint.argtypes = [gnutls_psk_server_credentials_t, c_char_p]
gnutls_psk_set_server_credentials_hint.restype = c_int

gnutls_psk_set_server_dh_params = libgnutls.gnutls_psk_set_server_dh_params
gnutls_psk_set_server_dh_params.argtypes = [gnutls_psk_server_credentials_t, gnutls_dh_params_t]
gnutls_psk_set_server_dh_params.restype = None

gnutls_psk_set_server_params_function = libgnutls.gnutls_psk_set_server_params_function
gnutls_psk_set_server_params_function.argtypes = [gnutls_psk_server_credentials_t, gnutls_params_function]
gnutls_psk_set_server_params_function.restype = None

gnutls_record_check_pending = libgnutls.gnutls_record_check_pending
gnutls_record_check_pending.argtypes = [gnutls_session_t]
gnutls_record_check_pending.restype = size_t

gnutls_record_disable_padding = libgnutls.gnutls_record_disable_padding
gnutls_record_disable_padding.argtypes = [gnutls_session_t]
gnutls_record_disable_padding.restype = None

gnutls_record_get_direction = libgnutls.gnutls_record_get_direction
gnutls_record_get_direction.argtypes = [gnutls_session_t]
gnutls_record_get_direction.restype = c_int

gnutls_record_get_max_size = libgnutls.gnutls_record_get_max_size
gnutls_record_get_max_size.argtypes = [gnutls_session_t]
gnutls_record_get_max_size.restype = size_t

gnutls_record_recv = libgnutls.gnutls_record_recv
gnutls_record_recv.argtypes = [gnutls_session_t, c_void_p, size_t]
gnutls_record_recv.restype = ssize_t

gnutls_record_send = libgnutls.gnutls_record_send
gnutls_record_send.argtypes = [gnutls_session_t, c_void_p, size_t]
gnutls_record_send.restype = ssize_t

gnutls_record_set_max_size = libgnutls.gnutls_record_set_max_size
gnutls_record_set_max_size.argtypes = [gnutls_session_t, size_t]
gnutls_record_set_max_size.restype = ssize_t

gnutls_rehandshake = libgnutls.gnutls_rehandshake
gnutls_rehandshake.argtypes = [gnutls_session_t]
gnutls_rehandshake.restype = c_int

gnutls_rsa_export_get_modulus_bits = libgnutls.gnutls_rsa_export_get_modulus_bits
gnutls_rsa_export_get_modulus_bits.argtypes = [gnutls_session_t]
gnutls_rsa_export_get_modulus_bits.restype = c_int

gnutls_rsa_export_get_pubkey = libgnutls.gnutls_rsa_export_get_pubkey
gnutls_rsa_export_get_pubkey.argtypes = [gnutls_session_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_rsa_export_get_pubkey.restype = c_int

gnutls_rsa_params_cpy = libgnutls.gnutls_rsa_params_cpy
gnutls_rsa_params_cpy.argtypes = [gnutls_rsa_params_t, gnutls_rsa_params_t]
gnutls_rsa_params_cpy.restype = c_int

gnutls_rsa_params_deinit = libgnutls.gnutls_rsa_params_deinit
gnutls_rsa_params_deinit.argtypes = [gnutls_rsa_params_t]
gnutls_rsa_params_deinit.restype = None

gnutls_rsa_params_export_pkcs1 = libgnutls.gnutls_rsa_params_export_pkcs1
gnutls_rsa_params_export_pkcs1.argtypes = [gnutls_rsa_params_t, gnutls_x509_crt_fmt_t, POINTER(c_ubyte), POINTER(size_t)]
gnutls_rsa_params_export_pkcs1.restype = c_int

gnutls_rsa_params_export_raw = libgnutls.gnutls_rsa_params_export_raw
gnutls_rsa_params_export_raw.argtypes = [gnutls_rsa_params_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(c_uint)]
gnutls_rsa_params_export_raw.restype = c_int

gnutls_rsa_params_generate2 = libgnutls.gnutls_rsa_params_generate2
gnutls_rsa_params_generate2.argtypes = [gnutls_rsa_params_t, c_uint]
gnutls_rsa_params_generate2.restype = c_int

gnutls_rsa_params_import_pkcs1 = libgnutls.gnutls_rsa_params_import_pkcs1
gnutls_rsa_params_import_pkcs1.argtypes = [gnutls_rsa_params_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_rsa_params_import_pkcs1.restype = c_int

gnutls_rsa_params_import_raw = libgnutls.gnutls_rsa_params_import_raw
gnutls_rsa_params_import_raw.argtypes = [gnutls_rsa_params_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_rsa_params_import_raw.restype = c_int

gnutls_rsa_params_init = libgnutls.gnutls_rsa_params_init
gnutls_rsa_params_init.argtypes = [POINTER(gnutls_rsa_params_t)]
gnutls_rsa_params_init.restype = c_int

gnutls_server_name_get = libgnutls.gnutls_server_name_get
gnutls_server_name_get.argtypes = [gnutls_session_t, c_void_p, POINTER(size_t), POINTER(c_uint), c_uint]
gnutls_server_name_get.restype = c_int

gnutls_server_name_set = libgnutls.gnutls_server_name_set
gnutls_server_name_set.argtypes = [gnutls_session_t, gnutls_server_name_type_t, c_void_p, size_t]
gnutls_server_name_set.restype = c_int

gnutls_session_enable_compatibility_mode = libgnutls.gnutls_session_enable_compatibility_mode
gnutls_session_enable_compatibility_mode.argtypes = [gnutls_session_t]
gnutls_session_enable_compatibility_mode.restype = None

gnutls_session_get_client_random = libgnutls.gnutls_session_get_client_random
gnutls_session_get_client_random.argtypes = [gnutls_session_t]
gnutls_session_get_client_random.restype = c_void_p

gnutls_session_get_data = libgnutls.gnutls_session_get_data
gnutls_session_get_data.argtypes = [gnutls_session_t, c_void_p, POINTER(size_t)]
gnutls_session_get_data.restype = c_int

gnutls_session_get_data2 = libgnutls.gnutls_session_get_data2
gnutls_session_get_data2.argtypes = [gnutls_session_t, POINTER(gnutls_datum_t)]
gnutls_session_get_data2.restype = c_int

gnutls_session_get_id = libgnutls.gnutls_session_get_id
gnutls_session_get_id.argtypes = [gnutls_session_t, c_void_p, POINTER(size_t)]
gnutls_session_get_id.restype = c_int

gnutls_session_get_master_secret = libgnutls.gnutls_session_get_master_secret
gnutls_session_get_master_secret.argtypes = [gnutls_session_t]
gnutls_session_get_master_secret.restype = c_void_p

gnutls_session_get_ptr = libgnutls.gnutls_session_get_ptr
gnutls_session_get_ptr.argtypes = [gnutls_session_t]
gnutls_session_get_ptr.restype = c_void_p

gnutls_session_get_server_random = libgnutls.gnutls_session_get_server_random
gnutls_session_get_server_random.argtypes = [gnutls_session_t]
gnutls_session_get_server_random.restype = c_void_p

gnutls_session_is_resumed = libgnutls.gnutls_session_is_resumed
gnutls_session_is_resumed.argtypes = [gnutls_session_t]
gnutls_session_is_resumed.restype = c_int

gnutls_session_set_data = libgnutls.gnutls_session_set_data
gnutls_session_set_data.argtypes = [gnutls_session_t, c_void_p, size_t]
gnutls_session_set_data.restype = c_int

gnutls_session_set_ptr = libgnutls.gnutls_session_set_ptr
gnutls_session_set_ptr.argtypes = [gnutls_session_t, c_void_p]
gnutls_session_set_ptr.restype = None

gnutls_set_default_export_priority = libgnutls.gnutls_set_default_export_priority
gnutls_set_default_export_priority.argtypes = [gnutls_session_t]
gnutls_set_default_export_priority.restype = c_int

gnutls_set_default_priority = libgnutls.gnutls_set_default_priority
gnutls_set_default_priority.argtypes = [gnutls_session_t]
gnutls_set_default_priority.restype = c_int

gnutls_sign_algorithm_get_name = libgnutls.gnutls_sign_algorithm_get_name
gnutls_sign_algorithm_get_name.argtypes = [gnutls_sign_algorithm_t]
gnutls_sign_algorithm_get_name.restype = c_char_p

gnutls_sign_callback_get = libgnutls.gnutls_sign_callback_get
gnutls_sign_callback_get.argtypes = [gnutls_session_t, POINTER(c_void_p)]
gnutls_sign_callback_get.restype = gnutls_sign_func

gnutls_sign_callback_set = libgnutls.gnutls_sign_callback_set
gnutls_sign_callback_set.argtypes = [gnutls_session_t, gnutls_sign_func, c_void_p]
gnutls_sign_callback_set.restype = None

gnutls_strerror = libgnutls.gnutls_strerror
gnutls_strerror.argtypes = [c_int]
gnutls_strerror.restype = c_char_p

gnutls_supplemental_get_name = libgnutls.gnutls_supplemental_get_name
gnutls_supplemental_get_name.argtypes = [gnutls_supplemental_data_format_type_t]
gnutls_supplemental_get_name.restype = c_char_p

gnutls_transport_get_ptr = libgnutls.gnutls_transport_get_ptr
gnutls_transport_get_ptr.argtypes = [gnutls_session_t]
gnutls_transport_get_ptr.restype = gnutls_transport_ptr_t

gnutls_transport_get_ptr2 = libgnutls.gnutls_transport_get_ptr2
gnutls_transport_get_ptr2.argtypes = [gnutls_session_t, POINTER(gnutls_transport_ptr_t), POINTER(gnutls_transport_ptr_t)]
gnutls_transport_get_ptr2.restype = None

gnutls_transport_set_errno = libgnutls.gnutls_transport_set_errno
gnutls_transport_set_errno.argtypes = [gnutls_session_t, c_int]
gnutls_transport_set_errno.restype = None

gnutls_transport_set_global_errno = libgnutls.gnutls_transport_set_global_errno
gnutls_transport_set_global_errno.argtypes = [c_int]
gnutls_transport_set_global_errno.restype = None

gnutls_transport_set_lowat = libgnutls.gnutls_transport_set_lowat
gnutls_transport_set_lowat.argtypes = [gnutls_session_t, c_int]
gnutls_transport_set_lowat.restype = None

gnutls_transport_set_ptr = libgnutls.gnutls_transport_set_ptr
gnutls_transport_set_ptr.argtypes = [gnutls_session_t, gnutls_transport_ptr_t]
gnutls_transport_set_ptr.restype = None

gnutls_transport_set_ptr2 = libgnutls.gnutls_transport_set_ptr2
gnutls_transport_set_ptr2.argtypes = [gnutls_session_t, gnutls_transport_ptr_t, gnutls_transport_ptr_t]
gnutls_transport_set_ptr2.restype = None

gnutls_transport_set_pull_function = libgnutls.gnutls_transport_set_pull_function
gnutls_transport_set_pull_function.argtypes = [gnutls_session_t, gnutls_pull_func]
gnutls_transport_set_pull_function.restype = None

gnutls_transport_set_push_function = libgnutls.gnutls_transport_set_push_function
gnutls_transport_set_push_function.argtypes = [gnutls_session_t, gnutls_push_func]
gnutls_transport_set_push_function.restype = None

gnutls_x509_crl_check_issuer = libgnutls.gnutls_x509_crl_check_issuer
gnutls_x509_crl_check_issuer.argtypes = [gnutls_x509_crl_t, gnutls_x509_crt_t]
gnutls_x509_crl_check_issuer.restype = c_int

gnutls_x509_crl_deinit = libgnutls.gnutls_x509_crl_deinit
gnutls_x509_crl_deinit.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_deinit.restype = None

gnutls_x509_crl_export = libgnutls.gnutls_x509_crl_export
gnutls_x509_crl_export.argtypes = [gnutls_x509_crl_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_x509_crl_export.restype = c_int

gnutls_x509_crl_get_crt_count = libgnutls.gnutls_x509_crl_get_crt_count
gnutls_x509_crl_get_crt_count.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_get_crt_count.restype = c_int

gnutls_x509_crl_get_crt_serial = libgnutls.gnutls_x509_crl_get_crt_serial
gnutls_x509_crl_get_crt_serial.argtypes = [gnutls_x509_crl_t, c_int, POINTER(c_ubyte), POINTER(size_t), POINTER(time_t)]
gnutls_x509_crl_get_crt_serial.restype = c_int

gnutls_x509_crl_get_dn_oid = libgnutls.gnutls_x509_crl_get_dn_oid
gnutls_x509_crl_get_dn_oid.argtypes = [gnutls_x509_crl_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crl_get_dn_oid.restype = c_int

gnutls_x509_crl_get_issuer_dn = libgnutls.gnutls_x509_crl_get_issuer_dn
gnutls_x509_crl_get_issuer_dn.argtypes = [gnutls_x509_crl_t, c_char_p, POINTER(size_t)]
gnutls_x509_crl_get_issuer_dn.restype = c_int

gnutls_x509_crl_get_issuer_dn_by_oid = libgnutls.gnutls_x509_crl_get_issuer_dn_by_oid
gnutls_x509_crl_get_issuer_dn_by_oid.argtypes = [gnutls_x509_crl_t, c_char_p, c_int, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_crl_get_issuer_dn_by_oid.restype = c_int

gnutls_x509_crl_get_next_update = libgnutls.gnutls_x509_crl_get_next_update
gnutls_x509_crl_get_next_update.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_get_next_update.restype = time_t
gnutls_x509_crl_get_next_update.errmsg = "cannot get CRL's next update time"

gnutls_x509_crl_get_signature = libgnutls.gnutls_x509_crl_get_signature
gnutls_x509_crl_get_signature.argtypes = [gnutls_x509_crl_t, c_char_p, POINTER(size_t)]
gnutls_x509_crl_get_signature.restype = c_int

gnutls_x509_crl_get_signature_algorithm = libgnutls.gnutls_x509_crl_get_signature_algorithm
gnutls_x509_crl_get_signature_algorithm.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_get_signature_algorithm.restype = c_int

gnutls_x509_crl_get_this_update = libgnutls.gnutls_x509_crl_get_this_update
gnutls_x509_crl_get_this_update.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_get_this_update.restype = time_t
gnutls_x509_crl_get_this_update.errmsg = "cannot get CRL's issue time"

gnutls_x509_crl_get_version = libgnutls.gnutls_x509_crl_get_version
gnutls_x509_crl_get_version.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_get_version.restype = c_int

gnutls_x509_crl_import = libgnutls.gnutls_x509_crl_import
gnutls_x509_crl_import.argtypes = [gnutls_x509_crl_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_x509_crl_import.restype = c_int

gnutls_x509_crl_init = libgnutls.gnutls_x509_crl_init
gnutls_x509_crl_init.argtypes = [POINTER(gnutls_x509_crl_t)]
gnutls_x509_crl_init.restype = c_int

gnutls_x509_crl_print = libgnutls.gnutls_x509_crl_print
gnutls_x509_crl_print.argtypes = [gnutls_x509_crl_t, gnutls_certificate_print_formats_t, POINTER(gnutls_datum_t)]
gnutls_x509_crl_print.restype = c_int

gnutls_x509_crl_set_crt = libgnutls.gnutls_x509_crl_set_crt
gnutls_x509_crl_set_crt.argtypes = [gnutls_x509_crl_t, gnutls_x509_crt_t, time_t]
gnutls_x509_crl_set_crt.restype = c_int

gnutls_x509_crl_set_crt_serial = libgnutls.gnutls_x509_crl_set_crt_serial
gnutls_x509_crl_set_crt_serial.argtypes = [gnutls_x509_crl_t, c_void_p, size_t, time_t]
gnutls_x509_crl_set_crt_serial.restype = c_int

gnutls_x509_crl_set_next_update = libgnutls.gnutls_x509_crl_set_next_update
gnutls_x509_crl_set_next_update.argtypes = [gnutls_x509_crl_t, time_t]
gnutls_x509_crl_set_next_update.restype = c_int

gnutls_x509_crl_set_this_update = libgnutls.gnutls_x509_crl_set_this_update
gnutls_x509_crl_set_this_update.argtypes = [gnutls_x509_crl_t, time_t]
gnutls_x509_crl_set_this_update.restype = c_int

gnutls_x509_crl_set_version = libgnutls.gnutls_x509_crl_set_version
gnutls_x509_crl_set_version.argtypes = [gnutls_x509_crl_t, c_uint]
gnutls_x509_crl_set_version.restype = c_int

gnutls_x509_crl_sign = libgnutls.gnutls_x509_crl_sign
gnutls_x509_crl_sign.argtypes = [gnutls_x509_crl_t, gnutls_x509_crt_t, gnutls_x509_privkey_t]
gnutls_x509_crl_sign.restype = c_int

gnutls_x509_crl_sign2 = libgnutls.gnutls_x509_crl_sign2
gnutls_x509_crl_sign2.argtypes = [gnutls_x509_crl_t, gnutls_x509_crt_t, gnutls_x509_privkey_t, gnutls_digest_algorithm_t, c_uint]
gnutls_x509_crl_sign2.restype = c_int

gnutls_x509_crl_verify = libgnutls.gnutls_x509_crl_verify
gnutls_x509_crl_verify.argtypes = [gnutls_x509_crl_t, POINTER(gnutls_x509_crt_t), c_int, c_uint, POINTER(c_uint)]
gnutls_x509_crl_verify.restype = c_int

gnutls_x509_crq_deinit = libgnutls.gnutls_x509_crq_deinit
gnutls_x509_crq_deinit.argtypes = [gnutls_x509_crq_t]
gnutls_x509_crq_deinit.restype = None

gnutls_x509_crq_export = libgnutls.gnutls_x509_crq_export
gnutls_x509_crq_export.argtypes = [gnutls_x509_crq_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_x509_crq_export.restype = c_int

gnutls_x509_crq_get_attribute_by_oid = libgnutls.gnutls_x509_crq_get_attribute_by_oid
gnutls_x509_crq_get_attribute_by_oid.argtypes = [gnutls_x509_crq_t, c_char_p, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crq_get_attribute_by_oid.restype = c_int

gnutls_x509_crq_get_challenge_password = libgnutls.gnutls_x509_crq_get_challenge_password
gnutls_x509_crq_get_challenge_password.argtypes = [gnutls_x509_crq_t, c_char_p, POINTER(size_t)]
gnutls_x509_crq_get_challenge_password.restype = c_int

gnutls_x509_crq_get_dn = libgnutls.gnutls_x509_crq_get_dn
gnutls_x509_crq_get_dn.argtypes = [gnutls_x509_crq_t, c_char_p, POINTER(size_t)]
gnutls_x509_crq_get_dn.restype = c_int

gnutls_x509_crq_get_dn_by_oid = libgnutls.gnutls_x509_crq_get_dn_by_oid
gnutls_x509_crq_get_dn_by_oid.argtypes = [gnutls_x509_crq_t, c_char_p, c_int, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_crq_get_dn_by_oid.restype = c_int

gnutls_x509_crq_get_dn_oid = libgnutls.gnutls_x509_crq_get_dn_oid
gnutls_x509_crq_get_dn_oid.argtypes = [gnutls_x509_crq_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crq_get_dn_oid.restype = c_int

gnutls_x509_crq_get_pk_algorithm = libgnutls.gnutls_x509_crq_get_pk_algorithm
gnutls_x509_crq_get_pk_algorithm.argtypes = [gnutls_x509_crq_t, POINTER(c_uint)]
gnutls_x509_crq_get_pk_algorithm.restype = c_int

gnutls_x509_crq_import = libgnutls.gnutls_x509_crq_import
gnutls_x509_crq_import.argtypes = [gnutls_x509_crq_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_x509_crq_import.restype = c_int

gnutls_x509_crq_init = libgnutls.gnutls_x509_crq_init
gnutls_x509_crq_init.argtypes = [POINTER(gnutls_x509_crq_t)]
gnutls_x509_crq_init.restype = c_int

gnutls_x509_crq_set_attribute_by_oid = libgnutls.gnutls_x509_crq_set_attribute_by_oid
gnutls_x509_crq_set_attribute_by_oid.argtypes = [gnutls_x509_crq_t, c_char_p, c_void_p, size_t]
gnutls_x509_crq_set_attribute_by_oid.restype = c_int

gnutls_x509_crq_set_challenge_password = libgnutls.gnutls_x509_crq_set_challenge_password
gnutls_x509_crq_set_challenge_password.argtypes = [gnutls_x509_crq_t, c_char_p]
gnutls_x509_crq_set_challenge_password.restype = c_int

gnutls_x509_crq_set_dn_by_oid = libgnutls.gnutls_x509_crq_set_dn_by_oid
gnutls_x509_crq_set_dn_by_oid.argtypes = [gnutls_x509_crq_t, c_char_p, c_uint, c_void_p, c_uint]
gnutls_x509_crq_set_dn_by_oid.restype = c_int

gnutls_x509_crq_set_key = libgnutls.gnutls_x509_crq_set_key
gnutls_x509_crq_set_key.argtypes = [gnutls_x509_crq_t, gnutls_x509_privkey_t]
gnutls_x509_crq_set_key.restype = c_int

gnutls_x509_crq_set_version = libgnutls.gnutls_x509_crq_set_version
gnutls_x509_crq_set_version.argtypes = [gnutls_x509_crq_t, c_uint]
gnutls_x509_crq_set_version.restype = c_int

gnutls_x509_crq_sign = libgnutls.gnutls_x509_crq_sign
gnutls_x509_crq_sign.argtypes = [gnutls_x509_crq_t, gnutls_x509_privkey_t]
gnutls_x509_crq_sign.restype = c_int

gnutls_x509_crq_sign2 = libgnutls.gnutls_x509_crq_sign2
gnutls_x509_crq_sign2.argtypes = [gnutls_x509_crq_t, gnutls_x509_privkey_t, gnutls_digest_algorithm_t, c_uint]
gnutls_x509_crq_sign2.restype = c_int

gnutls_x509_crt_check_hostname = libgnutls.gnutls_x509_crt_check_hostname
gnutls_x509_crt_check_hostname.argtypes = [gnutls_x509_crt_t, c_char_p]
gnutls_x509_crt_check_hostname.restype = c_int

gnutls_x509_crt_check_issuer = libgnutls.gnutls_x509_crt_check_issuer
gnutls_x509_crt_check_issuer.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_t]
gnutls_x509_crt_check_issuer.restype = c_int

gnutls_x509_crt_check_revocation = libgnutls.gnutls_x509_crt_check_revocation
gnutls_x509_crt_check_revocation.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_x509_crl_t), c_int]
gnutls_x509_crt_check_revocation.restype = c_int

gnutls_x509_crt_cpy_crl_dist_points = libgnutls.gnutls_x509_crt_cpy_crl_dist_points
gnutls_x509_crt_cpy_crl_dist_points.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_t]
gnutls_x509_crt_cpy_crl_dist_points.restype = c_int

gnutls_x509_crt_deinit = libgnutls.gnutls_x509_crt_deinit
gnutls_x509_crt_deinit.argtypes = [gnutls_x509_crt_t]
gnutls_x509_crt_deinit.restype = None

gnutls_x509_crt_export = libgnutls.gnutls_x509_crt_export
gnutls_x509_crt_export.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_x509_crt_export.restype = c_int

gnutls_x509_crt_get_activation_time = libgnutls.gnutls_x509_crt_get_activation_time
gnutls_x509_crt_get_activation_time.argtypes = [gnutls_x509_crt_t]
gnutls_x509_crt_get_activation_time.restype = time_t
gnutls_x509_crt_get_activation_time.errmsg = "cannot get X509 certificate activation time"

gnutls_x509_crt_get_authority_key_id = libgnutls.gnutls_x509_crt_get_authority_key_id
gnutls_x509_crt_get_authority_key_id.argtypes = [gnutls_x509_crt_t, c_void_p, POINTER(size_t), POINTER(c_uint)]
gnutls_x509_crt_get_authority_key_id.restype = c_int

gnutls_x509_crt_get_basic_constraints = libgnutls.gnutls_x509_crt_get_basic_constraints
gnutls_x509_crt_get_basic_constraints.argtypes = [gnutls_x509_crt_t, POINTER(c_uint), POINTER(c_int), POINTER(c_int)]
gnutls_x509_crt_get_basic_constraints.restype = c_int

gnutls_x509_crt_get_ca_status = libgnutls.gnutls_x509_crt_get_ca_status
gnutls_x509_crt_get_ca_status.argtypes = [gnutls_x509_crt_t, POINTER(c_uint)]
gnutls_x509_crt_get_ca_status.restype = c_int

gnutls_x509_crt_get_crl_dist_points = libgnutls.gnutls_x509_crt_get_crl_dist_points
gnutls_x509_crt_get_crl_dist_points.argtypes = [gnutls_x509_crt_t, c_uint, c_void_p, POINTER(size_t), POINTER(c_uint), POINTER(c_uint)]
gnutls_x509_crt_get_crl_dist_points.restype = c_int

gnutls_x509_crt_get_dn = libgnutls.gnutls_x509_crt_get_dn
gnutls_x509_crt_get_dn.argtypes = [gnutls_x509_crt_t, c_char_p, POINTER(size_t)]
gnutls_x509_crt_get_dn.restype = c_int

gnutls_x509_crt_get_dn_by_oid = libgnutls.gnutls_x509_crt_get_dn_by_oid
gnutls_x509_crt_get_dn_by_oid.argtypes = [gnutls_x509_crt_t, c_char_p, c_int, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_dn_by_oid.restype = c_int

gnutls_x509_crt_get_dn_oid = libgnutls.gnutls_x509_crt_get_dn_oid
gnutls_x509_crt_get_dn_oid.argtypes = [gnutls_x509_crt_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_dn_oid.restype = c_int

gnutls_x509_crt_get_expiration_time = libgnutls.gnutls_x509_crt_get_expiration_time
gnutls_x509_crt_get_expiration_time.argtypes = [gnutls_x509_crt_t]
gnutls_x509_crt_get_expiration_time.restype = time_t
gnutls_x509_crt_get_expiration_time.errmsg = "cannot get X509 certificate expiration time"

gnutls_x509_crt_get_extension_by_oid = libgnutls.gnutls_x509_crt_get_extension_by_oid
gnutls_x509_crt_get_extension_by_oid.argtypes = [gnutls_x509_crt_t, c_char_p, c_int, c_void_p, POINTER(size_t), POINTER(c_uint)]
gnutls_x509_crt_get_extension_by_oid.restype = c_int

gnutls_x509_crt_get_extension_data = libgnutls.gnutls_x509_crt_get_extension_data
gnutls_x509_crt_get_extension_data.argtypes = [gnutls_x509_crt_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_extension_data.restype = c_int

gnutls_x509_crt_get_extension_info = libgnutls.gnutls_x509_crt_get_extension_info
gnutls_x509_crt_get_extension_info.argtypes = [gnutls_x509_crt_t, c_int, c_void_p, POINTER(size_t), POINTER(c_int)]
gnutls_x509_crt_get_extension_info.restype = c_int

gnutls_x509_crt_get_extension_oid = libgnutls.gnutls_x509_crt_get_extension_oid
gnutls_x509_crt_get_extension_oid.argtypes = [gnutls_x509_crt_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_extension_oid.restype = c_int

gnutls_x509_crt_get_fingerprint = libgnutls.gnutls_x509_crt_get_fingerprint
gnutls_x509_crt_get_fingerprint.argtypes = [gnutls_x509_crt_t, gnutls_digest_algorithm_t, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_fingerprint.restype = c_int

gnutls_x509_crt_get_issuer = libgnutls.gnutls_x509_crt_get_issuer
gnutls_x509_crt_get_issuer.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_x509_dn_t)]
gnutls_x509_crt_get_issuer.restype = c_int

gnutls_x509_crt_get_issuer_dn = libgnutls.gnutls_x509_crt_get_issuer_dn
gnutls_x509_crt_get_issuer_dn.argtypes = [gnutls_x509_crt_t, c_char_p, POINTER(size_t)]
gnutls_x509_crt_get_issuer_dn.restype = c_int

gnutls_x509_crt_get_issuer_dn_by_oid = libgnutls.gnutls_x509_crt_get_issuer_dn_by_oid
gnutls_x509_crt_get_issuer_dn_by_oid.argtypes = [gnutls_x509_crt_t, c_char_p, c_int, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_issuer_dn_by_oid.restype = c_int

gnutls_x509_crt_get_issuer_dn_oid = libgnutls.gnutls_x509_crt_get_issuer_dn_oid
gnutls_x509_crt_get_issuer_dn_oid.argtypes = [gnutls_x509_crt_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_issuer_dn_oid.restype = c_int

gnutls_x509_crt_get_key_id = libgnutls.gnutls_x509_crt_get_key_id
gnutls_x509_crt_get_key_id.argtypes = [gnutls_x509_crt_t, c_uint, POINTER(c_ubyte), POINTER(size_t)]
gnutls_x509_crt_get_key_id.restype = c_int

gnutls_x509_crt_get_key_purpose_oid = libgnutls.gnutls_x509_crt_get_key_purpose_oid
gnutls_x509_crt_get_key_purpose_oid.argtypes = [gnutls_x509_crt_t, c_int, c_void_p, POINTER(size_t), POINTER(c_uint)]
gnutls_x509_crt_get_key_purpose_oid.restype = c_int

gnutls_x509_crt_get_key_usage = libgnutls.gnutls_x509_crt_get_key_usage
gnutls_x509_crt_get_key_usage.argtypes = [gnutls_x509_crt_t, POINTER(c_uint), POINTER(c_uint)]
gnutls_x509_crt_get_key_usage.restype = c_int

gnutls_x509_crt_get_pk_algorithm = libgnutls.gnutls_x509_crt_get_pk_algorithm
gnutls_x509_crt_get_pk_algorithm.argtypes = [gnutls_x509_crt_t, POINTER(c_uint)]
gnutls_x509_crt_get_pk_algorithm.restype = c_int

gnutls_x509_crt_get_pk_dsa_raw = libgnutls.gnutls_x509_crt_get_pk_dsa_raw
gnutls_x509_crt_get_pk_dsa_raw.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_crt_get_pk_dsa_raw.restype = c_int

gnutls_x509_crt_get_pk_rsa_raw = libgnutls.gnutls_x509_crt_get_pk_rsa_raw
gnutls_x509_crt_get_pk_rsa_raw.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_crt_get_pk_rsa_raw.restype = c_int

gnutls_x509_crt_get_proxy = libgnutls.gnutls_x509_crt_get_proxy
gnutls_x509_crt_get_proxy.argtypes = [gnutls_x509_crt_t, POINTER(c_uint), POINTER(c_int), POINTER(c_char_p), POINTER(c_char_p), POINTER(size_t)]
gnutls_x509_crt_get_proxy.restype = c_int

gnutls_x509_crt_get_raw_dn = libgnutls.gnutls_x509_crt_get_raw_dn
gnutls_x509_crt_get_raw_dn.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_datum_t)]
gnutls_x509_crt_get_raw_dn.restype = c_int

gnutls_x509_crt_get_raw_issuer_dn = libgnutls.gnutls_x509_crt_get_raw_issuer_dn
gnutls_x509_crt_get_raw_issuer_dn.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_datum_t)]
gnutls_x509_crt_get_raw_issuer_dn.restype = c_int

gnutls_x509_crt_get_serial = libgnutls.gnutls_x509_crt_get_serial
gnutls_x509_crt_get_serial.argtypes = [gnutls_x509_crt_t, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_serial.restype = c_int

gnutls_x509_crt_get_signature = libgnutls.gnutls_x509_crt_get_signature
gnutls_x509_crt_get_signature.argtypes = [gnutls_x509_crt_t, c_char_p, POINTER(size_t)]
gnutls_x509_crt_get_signature.restype = c_int

gnutls_x509_crt_get_signature_algorithm = libgnutls.gnutls_x509_crt_get_signature_algorithm
gnutls_x509_crt_get_signature_algorithm.argtypes = [gnutls_x509_crt_t]
gnutls_x509_crt_get_signature_algorithm.restype = c_int

gnutls_x509_crt_get_subject = libgnutls.gnutls_x509_crt_get_subject
gnutls_x509_crt_get_subject.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_x509_dn_t)]
gnutls_x509_crt_get_subject.restype = c_int

gnutls_x509_crt_get_subject_alt_name = libgnutls.gnutls_x509_crt_get_subject_alt_name
gnutls_x509_crt_get_subject_alt_name.argtypes = [gnutls_x509_crt_t, c_uint, c_void_p, POINTER(size_t), POINTER(c_uint)]
gnutls_x509_crt_get_subject_alt_name.restype = c_int

gnutls_x509_crt_get_subject_alt_name2 = libgnutls.gnutls_x509_crt_get_subject_alt_name2
gnutls_x509_crt_get_subject_alt_name2.argtypes = [gnutls_x509_crt_t, c_uint, c_void_p, POINTER(size_t), POINTER(c_uint), POINTER(c_uint)]
gnutls_x509_crt_get_subject_alt_name2.restype = c_int

gnutls_x509_crt_get_subject_alt_othername_oid = libgnutls.gnutls_x509_crt_get_subject_alt_othername_oid
gnutls_x509_crt_get_subject_alt_othername_oid.argtypes = [gnutls_x509_crt_t, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_subject_alt_othername_oid.restype = c_int

gnutls_x509_crt_get_subject_key_id = libgnutls.gnutls_x509_crt_get_subject_key_id
gnutls_x509_crt_get_subject_key_id.argtypes = [gnutls_x509_crt_t, c_void_p, POINTER(size_t), POINTER(c_uint)]
gnutls_x509_crt_get_subject_key_id.restype = c_int

gnutls_x509_crt_get_version = libgnutls.gnutls_x509_crt_get_version
gnutls_x509_crt_get_version.argtypes = [gnutls_x509_crt_t]
gnutls_x509_crt_get_version.restype = c_int

gnutls_x509_crt_import = libgnutls.gnutls_x509_crt_import
gnutls_x509_crt_import.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_x509_crt_import.restype = c_int

gnutls_x509_crt_init = libgnutls.gnutls_x509_crt_init
gnutls_x509_crt_init.argtypes = [POINTER(gnutls_x509_crt_t)]
gnutls_x509_crt_init.restype = c_int

gnutls_x509_crt_list_import = libgnutls.gnutls_x509_crt_list_import
gnutls_x509_crt_list_import.argtypes = [POINTER(gnutls_x509_crt_t), POINTER(c_uint), POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t, c_uint]
gnutls_x509_crt_list_import.restype = c_int

gnutls_x509_crt_list_verify = libgnutls.gnutls_x509_crt_list_verify
gnutls_x509_crt_list_verify.argtypes = [POINTER(gnutls_x509_crt_t), c_int, POINTER(gnutls_x509_crt_t), c_int, POINTER(gnutls_x509_crl_t), c_int, c_uint, POINTER(c_uint)]
gnutls_x509_crt_list_verify.restype = c_int

gnutls_x509_crt_print = libgnutls.gnutls_x509_crt_print
gnutls_x509_crt_print.argtypes = [gnutls_x509_crt_t, gnutls_certificate_print_formats_t, POINTER(gnutls_datum_t)]
gnutls_x509_crt_print.restype = c_int

gnutls_x509_crt_set_activation_time = libgnutls.gnutls_x509_crt_set_activation_time
gnutls_x509_crt_set_activation_time.argtypes = [gnutls_x509_crt_t, time_t]
gnutls_x509_crt_set_activation_time.restype = c_int

gnutls_x509_crt_set_authority_key_id = libgnutls.gnutls_x509_crt_set_authority_key_id
gnutls_x509_crt_set_authority_key_id.argtypes = [gnutls_x509_crt_t, c_void_p, size_t]
gnutls_x509_crt_set_authority_key_id.restype = c_int

gnutls_x509_crt_set_basic_constraints = libgnutls.gnutls_x509_crt_set_basic_constraints
gnutls_x509_crt_set_basic_constraints.argtypes = [gnutls_x509_crt_t, c_uint, c_int]
gnutls_x509_crt_set_basic_constraints.restype = c_int

gnutls_x509_crt_set_ca_status = libgnutls.gnutls_x509_crt_set_ca_status
gnutls_x509_crt_set_ca_status.argtypes = [gnutls_x509_crt_t, c_uint]
gnutls_x509_crt_set_ca_status.restype = c_int

gnutls_x509_crt_set_crl_dist_points = libgnutls.gnutls_x509_crt_set_crl_dist_points
gnutls_x509_crt_set_crl_dist_points.argtypes = [gnutls_x509_crt_t, gnutls_x509_subject_alt_name_t, c_void_p, c_uint]
gnutls_x509_crt_set_crl_dist_points.restype = c_int

gnutls_x509_crt_set_crq = libgnutls.gnutls_x509_crt_set_crq
gnutls_x509_crt_set_crq.argtypes = [gnutls_x509_crt_t, gnutls_x509_crq_t]
gnutls_x509_crt_set_crq.restype = c_int

gnutls_x509_crt_set_dn_by_oid = libgnutls.gnutls_x509_crt_set_dn_by_oid
gnutls_x509_crt_set_dn_by_oid.argtypes = [gnutls_x509_crt_t, c_char_p, c_uint, c_void_p, c_uint]
gnutls_x509_crt_set_dn_by_oid.restype = c_int

gnutls_x509_crt_set_expiration_time = libgnutls.gnutls_x509_crt_set_expiration_time
gnutls_x509_crt_set_expiration_time.argtypes = [gnutls_x509_crt_t, time_t]
gnutls_x509_crt_set_expiration_time.restype = c_int

gnutls_x509_crt_set_extension_by_oid = libgnutls.gnutls_x509_crt_set_extension_by_oid
gnutls_x509_crt_set_extension_by_oid.argtypes = [gnutls_x509_crt_t, c_char_p, c_void_p, size_t, c_uint]
gnutls_x509_crt_set_extension_by_oid.restype = c_int

gnutls_x509_crt_set_issuer_dn_by_oid = libgnutls.gnutls_x509_crt_set_issuer_dn_by_oid
gnutls_x509_crt_set_issuer_dn_by_oid.argtypes = [gnutls_x509_crt_t, c_char_p, c_uint, c_void_p, c_uint]
gnutls_x509_crt_set_issuer_dn_by_oid.restype = c_int

gnutls_x509_crt_set_key = libgnutls.gnutls_x509_crt_set_key
gnutls_x509_crt_set_key.argtypes = [gnutls_x509_crt_t, gnutls_x509_privkey_t]
gnutls_x509_crt_set_key.restype = c_int

gnutls_x509_crt_set_key_purpose_oid = libgnutls.gnutls_x509_crt_set_key_purpose_oid
gnutls_x509_crt_set_key_purpose_oid.argtypes = [gnutls_x509_crt_t, c_void_p, c_uint]
gnutls_x509_crt_set_key_purpose_oid.restype = c_int

gnutls_x509_crt_set_key_usage = libgnutls.gnutls_x509_crt_set_key_usage
gnutls_x509_crt_set_key_usage.argtypes = [gnutls_x509_crt_t, c_uint]
gnutls_x509_crt_set_key_usage.restype = c_int

gnutls_x509_crt_set_proxy = libgnutls.gnutls_x509_crt_set_proxy
gnutls_x509_crt_set_proxy.argtypes = [gnutls_x509_crt_t, c_int, c_char_p, c_char_p, size_t]
gnutls_x509_crt_set_proxy.restype = c_int

gnutls_x509_crt_set_proxy_dn = libgnutls.gnutls_x509_crt_set_proxy_dn
gnutls_x509_crt_set_proxy_dn.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_t, c_uint, c_void_p, c_uint]
gnutls_x509_crt_set_proxy_dn.restype = c_int

gnutls_x509_crt_set_serial = libgnutls.gnutls_x509_crt_set_serial
gnutls_x509_crt_set_serial.argtypes = [gnutls_x509_crt_t, c_void_p, size_t]
gnutls_x509_crt_set_serial.restype = c_int

gnutls_x509_crt_set_subject_alternative_name = libgnutls.gnutls_x509_crt_set_subject_alternative_name
gnutls_x509_crt_set_subject_alternative_name.argtypes = [gnutls_x509_crt_t, gnutls_x509_subject_alt_name_t, c_char_p]
gnutls_x509_crt_set_subject_alternative_name.restype = c_int

gnutls_x509_crt_set_subject_key_id = libgnutls.gnutls_x509_crt_set_subject_key_id
gnutls_x509_crt_set_subject_key_id.argtypes = [gnutls_x509_crt_t, c_void_p, size_t]
gnutls_x509_crt_set_subject_key_id.restype = c_int

gnutls_x509_crt_set_version = libgnutls.gnutls_x509_crt_set_version
gnutls_x509_crt_set_version.argtypes = [gnutls_x509_crt_t, c_uint]
gnutls_x509_crt_set_version.restype = c_int

gnutls_x509_crt_sign = libgnutls.gnutls_x509_crt_sign
gnutls_x509_crt_sign.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_t, gnutls_x509_privkey_t]
gnutls_x509_crt_sign.restype = c_int

gnutls_x509_crt_sign2 = libgnutls.gnutls_x509_crt_sign2
gnutls_x509_crt_sign2.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_t, gnutls_x509_privkey_t, gnutls_digest_algorithm_t, c_uint]
gnutls_x509_crt_sign2.restype = c_int

gnutls_x509_crt_verify = libgnutls.gnutls_x509_crt_verify
gnutls_x509_crt_verify.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_x509_crt_t), c_int, c_uint, POINTER(c_uint)]
gnutls_x509_crt_verify.restype = c_int

gnutls_x509_crt_verify_data = libgnutls.gnutls_x509_crt_verify_data
gnutls_x509_crt_verify_data.argtypes = [gnutls_x509_crt_t, c_uint, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_crt_verify_data.restype = c_int

gnutls_x509_dn_deinit = libgnutls.gnutls_x509_dn_deinit
gnutls_x509_dn_deinit.argtypes = [gnutls_x509_dn_t]
gnutls_x509_dn_deinit.restype = None

gnutls_x509_dn_export = libgnutls.gnutls_x509_dn_export
gnutls_x509_dn_export.argtypes = [gnutls_x509_dn_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_x509_dn_export.restype = c_int

gnutls_x509_dn_get_rdn_ava = libgnutls.gnutls_x509_dn_get_rdn_ava
gnutls_x509_dn_get_rdn_ava.argtypes = [gnutls_x509_dn_t, c_int, c_int, POINTER(gnutls_x509_ava_st)]
gnutls_x509_dn_get_rdn_ava.restype = c_int

gnutls_x509_dn_import = libgnutls.gnutls_x509_dn_import
gnutls_x509_dn_import.argtypes = [gnutls_x509_dn_t, POINTER(gnutls_datum_t)]
gnutls_x509_dn_import.restype = c_int

gnutls_x509_dn_init = libgnutls.gnutls_x509_dn_init
gnutls_x509_dn_init.argtypes = [POINTER(gnutls_x509_dn_t)]
gnutls_x509_dn_init.restype = c_int

gnutls_x509_dn_oid_known = libgnutls.gnutls_x509_dn_oid_known
gnutls_x509_dn_oid_known.argtypes = [c_char_p]
gnutls_x509_dn_oid_known.restype = c_int

gnutls_x509_privkey_cpy = libgnutls.gnutls_x509_privkey_cpy
gnutls_x509_privkey_cpy.argtypes = [gnutls_x509_privkey_t, gnutls_x509_privkey_t]
gnutls_x509_privkey_cpy.restype = c_int

gnutls_x509_privkey_deinit = libgnutls.gnutls_x509_privkey_deinit
gnutls_x509_privkey_deinit.argtypes = [gnutls_x509_privkey_t]
gnutls_x509_privkey_deinit.restype = None

gnutls_x509_privkey_export = libgnutls.gnutls_x509_privkey_export
gnutls_x509_privkey_export.argtypes = [gnutls_x509_privkey_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_x509_privkey_export.restype = c_int

gnutls_x509_privkey_export_dsa_raw = libgnutls.gnutls_x509_privkey_export_dsa_raw
gnutls_x509_privkey_export_dsa_raw.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_privkey_export_dsa_raw.restype = c_int

gnutls_x509_privkey_export_pkcs8 = libgnutls.gnutls_x509_privkey_export_pkcs8
gnutls_x509_privkey_export_pkcs8.argtypes = [gnutls_x509_privkey_t, gnutls_x509_crt_fmt_t, c_char_p, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_privkey_export_pkcs8.restype = c_int

gnutls_x509_privkey_export_rsa_raw = libgnutls.gnutls_x509_privkey_export_rsa_raw
gnutls_x509_privkey_export_rsa_raw.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_privkey_export_rsa_raw.restype = c_int

gnutls_x509_privkey_fix = libgnutls.gnutls_x509_privkey_fix
gnutls_x509_privkey_fix.argtypes = [gnutls_x509_privkey_t]
gnutls_x509_privkey_fix.restype = c_int

gnutls_x509_privkey_generate = libgnutls.gnutls_x509_privkey_generate
gnutls_x509_privkey_generate.argtypes = [gnutls_x509_privkey_t, gnutls_pk_algorithm_t, c_uint, c_uint]
gnutls_x509_privkey_generate.restype = c_int

gnutls_x509_privkey_get_key_id = libgnutls.gnutls_x509_privkey_get_key_id
gnutls_x509_privkey_get_key_id.argtypes = [gnutls_x509_privkey_t, c_uint, POINTER(c_ubyte), POINTER(size_t)]
gnutls_x509_privkey_get_key_id.restype = c_int

gnutls_x509_privkey_get_pk_algorithm = libgnutls.gnutls_x509_privkey_get_pk_algorithm
gnutls_x509_privkey_get_pk_algorithm.argtypes = [gnutls_x509_privkey_t]
gnutls_x509_privkey_get_pk_algorithm.restype = c_int

gnutls_x509_privkey_import = libgnutls.gnutls_x509_privkey_import
gnutls_x509_privkey_import.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_x509_privkey_import.restype = c_int

gnutls_x509_privkey_import_dsa_raw = libgnutls.gnutls_x509_privkey_import_dsa_raw
gnutls_x509_privkey_import_dsa_raw.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_privkey_import_dsa_raw.restype = c_int

gnutls_x509_privkey_import_pkcs8 = libgnutls.gnutls_x509_privkey_import_pkcs8
gnutls_x509_privkey_import_pkcs8.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t, c_char_p, c_uint]
gnutls_x509_privkey_import_pkcs8.restype = c_int

gnutls_x509_privkey_import_rsa_raw = libgnutls.gnutls_x509_privkey_import_rsa_raw
gnutls_x509_privkey_import_rsa_raw.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_privkey_import_rsa_raw.restype = c_int

gnutls_x509_privkey_init = libgnutls.gnutls_x509_privkey_init
gnutls_x509_privkey_init.argtypes = [POINTER(gnutls_x509_privkey_t)]
gnutls_x509_privkey_init.restype = c_int

gnutls_x509_privkey_sign_data = libgnutls.gnutls_x509_privkey_sign_data
gnutls_x509_privkey_sign_data.argtypes = [gnutls_x509_privkey_t, gnutls_digest_algorithm_t, c_uint, POINTER(gnutls_datum_t), c_void_p, POINTER(size_t)]
gnutls_x509_privkey_sign_data.restype = c_int

gnutls_x509_privkey_sign_hash = libgnutls.gnutls_x509_privkey_sign_hash
gnutls_x509_privkey_sign_hash.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_privkey_sign_hash.restype = c_int

gnutls_x509_privkey_verify_data = libgnutls.gnutls_x509_privkey_verify_data
gnutls_x509_privkey_verify_data.argtypes = [gnutls_x509_privkey_t, c_uint, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_privkey_verify_data.restype = c_int

gnutls_x509_rdn_get = libgnutls.gnutls_x509_rdn_get
gnutls_x509_rdn_get.argtypes = [POINTER(gnutls_datum_t), c_char_p, POINTER(size_t)]
gnutls_x509_rdn_get.restype = c_int

gnutls_x509_rdn_get_by_oid = libgnutls.gnutls_x509_rdn_get_by_oid
gnutls_x509_rdn_get_by_oid.argtypes = [POINTER(gnutls_datum_t), c_char_p, c_int, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_rdn_get_by_oid.restype = c_int

gnutls_x509_rdn_get_oid = libgnutls.gnutls_x509_rdn_get_oid
gnutls_x509_rdn_get_oid.argtypes = [POINTER(gnutls_datum_t), c_int, c_void_p, POINTER(size_t)]
gnutls_x509_rdn_get_oid.restype = c_int


# The openpgp related functions are not always present (on windows for example they are missing)
#

try:
    gnutls_certificate_get_openpgp_keyring = libgnutls.gnutls_certificate_get_openpgp_keyring
except AttributeError:
    pass
else:
    gnutls_certificate_get_openpgp_keyring = libgnutls.gnutls_certificate_get_openpgp_keyring
    gnutls_certificate_get_openpgp_keyring.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_openpgp_keyring_t)]
    gnutls_certificate_get_openpgp_keyring.restype = None

    gnutls_certificate_set_openpgp_key = libgnutls.gnutls_certificate_set_openpgp_key
    gnutls_certificate_set_openpgp_key.argtypes = [gnutls_certificate_credentials_t, gnutls_openpgp_crt_t, gnutls_openpgp_privkey_t]
    gnutls_certificate_set_openpgp_key.restype = c_int

    gnutls_certificate_set_openpgp_key_file = libgnutls.gnutls_certificate_set_openpgp_key_file
    gnutls_certificate_set_openpgp_key_file.argtypes = [gnutls_certificate_credentials_t, c_char_p, c_char_p, gnutls_openpgp_crt_fmt_t]
    gnutls_certificate_set_openpgp_key_file.restype = c_int

    gnutls_certificate_set_openpgp_key_file2 = libgnutls.gnutls_certificate_set_openpgp_key_file2
    gnutls_certificate_set_openpgp_key_file2.argtypes = [gnutls_certificate_credentials_t, c_char_p, c_char_p, c_char_p, gnutls_openpgp_crt_fmt_t]
    gnutls_certificate_set_openpgp_key_file2.restype = c_int

    gnutls_certificate_set_openpgp_key_mem = libgnutls.gnutls_certificate_set_openpgp_key_mem
    gnutls_certificate_set_openpgp_key_mem.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), gnutls_openpgp_crt_fmt_t]
    gnutls_certificate_set_openpgp_key_mem.restype = c_int

    gnutls_certificate_set_openpgp_key_mem2 = libgnutls.gnutls_certificate_set_openpgp_key_mem2
    gnutls_certificate_set_openpgp_key_mem2.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), c_char_p, gnutls_openpgp_crt_fmt_t]
    gnutls_certificate_set_openpgp_key_mem2.restype = c_int

    gnutls_certificate_set_openpgp_keyring_file = libgnutls.gnutls_certificate_set_openpgp_keyring_file
    gnutls_certificate_set_openpgp_keyring_file.argtypes = [gnutls_certificate_credentials_t, c_char_p, gnutls_openpgp_crt_fmt_t]
    gnutls_certificate_set_openpgp_keyring_file.restype = c_int

    gnutls_certificate_set_openpgp_keyring_mem = libgnutls.gnutls_certificate_set_openpgp_keyring_mem
    gnutls_certificate_set_openpgp_keyring_mem.argtypes = [gnutls_certificate_credentials_t, POINTER(c_ubyte), size_t, gnutls_openpgp_crt_fmt_t]
    gnutls_certificate_set_openpgp_keyring_mem.restype = c_int

    gnutls_openpgp_crt_check_hostname = libgnutls.gnutls_openpgp_crt_check_hostname
    gnutls_openpgp_crt_check_hostname.argtypes = [gnutls_openpgp_crt_t, c_char_p]
    gnutls_openpgp_crt_check_hostname.restype = c_int

    gnutls_openpgp_crt_deinit = libgnutls.gnutls_openpgp_crt_deinit
    gnutls_openpgp_crt_deinit.argtypes = [gnutls_openpgp_crt_t]
    gnutls_openpgp_crt_deinit.restype = None

    gnutls_openpgp_crt_export = libgnutls.gnutls_openpgp_crt_export
    gnutls_openpgp_crt_export.argtypes = [gnutls_openpgp_crt_t, gnutls_openpgp_crt_fmt_t, c_void_p, POINTER(size_t)]
    gnutls_openpgp_crt_export.restype = c_int

    gnutls_openpgp_crt_get_auth_subkey = libgnutls.gnutls_openpgp_crt_get_auth_subkey
    gnutls_openpgp_crt_get_auth_subkey.argtypes = [gnutls_openpgp_crt_t, POINTER(c_ubyte), c_uint]
    gnutls_openpgp_crt_get_auth_subkey.restype = c_int

    gnutls_openpgp_crt_get_creation_time = libgnutls.gnutls_openpgp_crt_get_creation_time
    gnutls_openpgp_crt_get_creation_time.argtypes = [gnutls_openpgp_crt_t]
    gnutls_openpgp_crt_get_creation_time.restype = time_t
    gnutls_openpgp_crt_get_creation_time.errmsg = "cannot get OpenPGP key creation time"

    gnutls_openpgp_crt_get_expiration_time = libgnutls.gnutls_openpgp_crt_get_expiration_time
    gnutls_openpgp_crt_get_expiration_time.argtypes = [gnutls_openpgp_crt_t]
    gnutls_openpgp_crt_get_expiration_time.restype = time_t
    gnutls_openpgp_crt_get_expiration_time.errmsg = "cannot get OpenPGP key expiration time"

    gnutls_openpgp_crt_get_fingerprint = libgnutls.gnutls_openpgp_crt_get_fingerprint
    gnutls_openpgp_crt_get_fingerprint.argtypes = [gnutls_openpgp_crt_t, c_void_p, POINTER(size_t)]
    gnutls_openpgp_crt_get_fingerprint.restype = c_int

    gnutls_openpgp_crt_get_key_id = libgnutls.gnutls_openpgp_crt_get_key_id
    gnutls_openpgp_crt_get_key_id.argtypes = [gnutls_openpgp_crt_t, POINTER(c_ubyte)]
    gnutls_openpgp_crt_get_key_id.restype = c_int

    gnutls_openpgp_crt_get_key_usage = libgnutls.gnutls_openpgp_crt_get_key_usage
    gnutls_openpgp_crt_get_key_usage.argtypes = [gnutls_openpgp_crt_t, POINTER(c_uint)]
    gnutls_openpgp_crt_get_key_usage.restype = c_int

    gnutls_openpgp_crt_get_name = libgnutls.gnutls_openpgp_crt_get_name
    gnutls_openpgp_crt_get_name.argtypes = [gnutls_openpgp_crt_t, c_int, c_char_p, POINTER(size_t)]
    gnutls_openpgp_crt_get_name.restype = c_int

    gnutls_openpgp_crt_get_pk_algorithm = libgnutls.gnutls_openpgp_crt_get_pk_algorithm
    gnutls_openpgp_crt_get_pk_algorithm.argtypes = [gnutls_openpgp_crt_t, POINTER(c_uint)]
    gnutls_openpgp_crt_get_pk_algorithm.restype = gnutls_pk_algorithm_t

    gnutls_openpgp_crt_get_pk_dsa_raw = libgnutls.gnutls_openpgp_crt_get_pk_dsa_raw
    gnutls_openpgp_crt_get_pk_dsa_raw.argtypes = [gnutls_openpgp_crt_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_openpgp_crt_get_pk_dsa_raw.restype = c_int

    gnutls_openpgp_crt_get_pk_rsa_raw = libgnutls.gnutls_openpgp_crt_get_pk_rsa_raw
    gnutls_openpgp_crt_get_pk_rsa_raw.argtypes = [gnutls_openpgp_crt_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_openpgp_crt_get_pk_rsa_raw.restype = c_int

    gnutls_openpgp_crt_get_preferred_key_id = libgnutls.gnutls_openpgp_crt_get_preferred_key_id
    gnutls_openpgp_crt_get_preferred_key_id.argtypes = [gnutls_openpgp_crt_t, POINTER(c_ubyte)]
    gnutls_openpgp_crt_get_preferred_key_id.restype = c_int

    gnutls_openpgp_crt_get_revoked_status = libgnutls.gnutls_openpgp_crt_get_revoked_status
    gnutls_openpgp_crt_get_revoked_status.argtypes = [gnutls_openpgp_crt_t]
    gnutls_openpgp_crt_get_revoked_status.restype = c_int

    gnutls_openpgp_crt_get_subkey_count = libgnutls.gnutls_openpgp_crt_get_subkey_count
    gnutls_openpgp_crt_get_subkey_count.argtypes = [gnutls_openpgp_crt_t]
    gnutls_openpgp_crt_get_subkey_count.restype = c_int

    gnutls_openpgp_crt_get_subkey_creation_time = libgnutls.gnutls_openpgp_crt_get_subkey_creation_time
    gnutls_openpgp_crt_get_subkey_creation_time.argtypes = [gnutls_openpgp_crt_t, c_uint]
    gnutls_openpgp_crt_get_subkey_creation_time.restype = time_t
    gnutls_openpgp_crt_get_subkey_creation_time.errmsg = "cannot get OpenPGP subkey creation time"

    gnutls_openpgp_crt_get_subkey_expiration_time = libgnutls.gnutls_openpgp_crt_get_subkey_expiration_time
    gnutls_openpgp_crt_get_subkey_expiration_time.argtypes = [gnutls_openpgp_crt_t, c_uint]
    gnutls_openpgp_crt_get_subkey_expiration_time.restype = time_t
    gnutls_openpgp_crt_get_subkey_expiration_time.errmsg = "cannot get OpenPGP subkey expiration time"

    gnutls_openpgp_crt_get_subkey_fingerprint = libgnutls.gnutls_openpgp_crt_get_subkey_fingerprint
    gnutls_openpgp_crt_get_subkey_fingerprint.argtypes = [gnutls_openpgp_crt_t, c_uint, c_void_p, POINTER(size_t)]
    gnutls_openpgp_crt_get_subkey_fingerprint.restype = c_int

    gnutls_openpgp_crt_get_subkey_id = libgnutls.gnutls_openpgp_crt_get_subkey_id
    gnutls_openpgp_crt_get_subkey_id.argtypes = [gnutls_openpgp_crt_t, c_uint, POINTER(c_ubyte)]
    gnutls_openpgp_crt_get_subkey_id.restype = c_int

    gnutls_openpgp_crt_get_subkey_idx = libgnutls.gnutls_openpgp_crt_get_subkey_idx
    gnutls_openpgp_crt_get_subkey_idx.argtypes = [gnutls_openpgp_crt_t, POINTER(c_ubyte)]
    gnutls_openpgp_crt_get_subkey_idx.restype = c_int

    gnutls_openpgp_crt_get_subkey_pk_algorithm = libgnutls.gnutls_openpgp_crt_get_subkey_pk_algorithm
    gnutls_openpgp_crt_get_subkey_pk_algorithm.argtypes = [gnutls_openpgp_crt_t, c_uint, POINTER(c_uint)]
    gnutls_openpgp_crt_get_subkey_pk_algorithm.restype = gnutls_pk_algorithm_t

    gnutls_openpgp_crt_get_subkey_pk_dsa_raw = libgnutls.gnutls_openpgp_crt_get_subkey_pk_dsa_raw
    gnutls_openpgp_crt_get_subkey_pk_dsa_raw.argtypes = [gnutls_openpgp_crt_t, c_uint, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_openpgp_crt_get_subkey_pk_dsa_raw.restype = c_int

    gnutls_openpgp_crt_get_subkey_pk_rsa_raw = libgnutls.gnutls_openpgp_crt_get_subkey_pk_rsa_raw
    gnutls_openpgp_crt_get_subkey_pk_rsa_raw.argtypes = [gnutls_openpgp_crt_t, c_uint, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_openpgp_crt_get_subkey_pk_rsa_raw.restype = c_int

    gnutls_openpgp_crt_get_subkey_revoked_status = libgnutls.gnutls_openpgp_crt_get_subkey_revoked_status
    gnutls_openpgp_crt_get_subkey_revoked_status.argtypes = [gnutls_openpgp_crt_t, c_uint]
    gnutls_openpgp_crt_get_subkey_revoked_status.restype = c_int

    gnutls_openpgp_crt_get_subkey_usage = libgnutls.gnutls_openpgp_crt_get_subkey_usage
    gnutls_openpgp_crt_get_subkey_usage.argtypes = [gnutls_openpgp_crt_t, c_uint, POINTER(c_uint)]
    gnutls_openpgp_crt_get_subkey_usage.restype = c_int

    gnutls_openpgp_crt_get_version = libgnutls.gnutls_openpgp_crt_get_version
    gnutls_openpgp_crt_get_version.argtypes = [gnutls_openpgp_crt_t]
    gnutls_openpgp_crt_get_version.restype = c_int

    gnutls_openpgp_crt_import = libgnutls.gnutls_openpgp_crt_import
    gnutls_openpgp_crt_import.argtypes = [gnutls_openpgp_crt_t, POINTER(gnutls_datum_t), gnutls_openpgp_crt_fmt_t]
    gnutls_openpgp_crt_import.restype = c_int

    gnutls_openpgp_crt_init = libgnutls.gnutls_openpgp_crt_init
    gnutls_openpgp_crt_init.argtypes = [POINTER(gnutls_openpgp_crt_t)]
    gnutls_openpgp_crt_init.restype = c_int

    gnutls_openpgp_crt_print = libgnutls.gnutls_openpgp_crt_print
    gnutls_openpgp_crt_print.argtypes = [gnutls_openpgp_crt_t, gnutls_certificate_print_formats_t, POINTER(gnutls_datum_t)]
    gnutls_openpgp_crt_print.restype = c_int

    gnutls_openpgp_crt_set_preferred_key_id = libgnutls.gnutls_openpgp_crt_set_preferred_key_id
    gnutls_openpgp_crt_set_preferred_key_id.argtypes = [gnutls_openpgp_crt_t, POINTER(c_ubyte)]
    gnutls_openpgp_crt_set_preferred_key_id.restype = c_int

    gnutls_openpgp_crt_verify_ring = libgnutls.gnutls_openpgp_crt_verify_ring
    gnutls_openpgp_crt_verify_ring.argtypes = [gnutls_openpgp_crt_t, gnutls_openpgp_keyring_t, c_uint, POINTER(c_uint)]
    gnutls_openpgp_crt_verify_ring.restype = c_int

    gnutls_openpgp_crt_verify_self = libgnutls.gnutls_openpgp_crt_verify_self
    gnutls_openpgp_crt_verify_self.argtypes = [gnutls_openpgp_crt_t, c_uint, POINTER(c_uint)]
    gnutls_openpgp_crt_verify_self.restype = c_int

    gnutls_openpgp_keyring_check_id = libgnutls.gnutls_openpgp_keyring_check_id
    gnutls_openpgp_keyring_check_id.argtypes = [gnutls_openpgp_keyring_t, POINTER(c_ubyte), c_uint]
    gnutls_openpgp_keyring_check_id.restype = c_int

    gnutls_openpgp_keyring_deinit = libgnutls.gnutls_openpgp_keyring_deinit
    gnutls_openpgp_keyring_deinit.argtypes = [gnutls_openpgp_keyring_t]
    gnutls_openpgp_keyring_deinit.restype = None

    gnutls_openpgp_keyring_get_crt = libgnutls.gnutls_openpgp_keyring_get_crt
    gnutls_openpgp_keyring_get_crt.argtypes = [gnutls_openpgp_keyring_t, c_uint, POINTER(gnutls_openpgp_crt_t)]
    gnutls_openpgp_keyring_get_crt.restype = c_int

    gnutls_openpgp_keyring_get_crt_count = libgnutls.gnutls_openpgp_keyring_get_crt_count
    gnutls_openpgp_keyring_get_crt_count.argtypes = [gnutls_openpgp_keyring_t]
    gnutls_openpgp_keyring_get_crt_count.restype = c_int

    gnutls_openpgp_keyring_import = libgnutls.gnutls_openpgp_keyring_import
    gnutls_openpgp_keyring_import.argtypes = [gnutls_openpgp_keyring_t, POINTER(gnutls_datum_t), gnutls_openpgp_crt_fmt_t]
    gnutls_openpgp_keyring_import.restype = c_int

    gnutls_openpgp_keyring_init = libgnutls.gnutls_openpgp_keyring_init
    gnutls_openpgp_keyring_init.argtypes = [POINTER(gnutls_openpgp_keyring_t)]
    gnutls_openpgp_keyring_init.restype = c_int

    gnutls_openpgp_privkey_deinit = libgnutls.gnutls_openpgp_privkey_deinit
    gnutls_openpgp_privkey_deinit.argtypes = [gnutls_openpgp_privkey_t]
    gnutls_openpgp_privkey_deinit.restype = None

    gnutls_openpgp_privkey_export = libgnutls.gnutls_openpgp_privkey_export
    gnutls_openpgp_privkey_export.argtypes = [gnutls_openpgp_privkey_t, gnutls_openpgp_crt_fmt_t, c_char_p, c_uint, c_void_p, POINTER(size_t)]
    gnutls_openpgp_privkey_export.restype = c_int

    gnutls_openpgp_privkey_export_dsa_raw = libgnutls.gnutls_openpgp_privkey_export_dsa_raw
    gnutls_openpgp_privkey_export_dsa_raw.argtypes = [gnutls_openpgp_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_openpgp_privkey_export_dsa_raw.restype = c_int

    gnutls_openpgp_privkey_export_rsa_raw = libgnutls.gnutls_openpgp_privkey_export_rsa_raw
    gnutls_openpgp_privkey_export_rsa_raw.argtypes = [gnutls_openpgp_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_openpgp_privkey_export_rsa_raw.restype = c_int

    gnutls_openpgp_privkey_export_subkey_dsa_raw = libgnutls.gnutls_openpgp_privkey_export_subkey_dsa_raw
    gnutls_openpgp_privkey_export_subkey_dsa_raw.argtypes = [gnutls_openpgp_privkey_t, c_uint, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_openpgp_privkey_export_subkey_dsa_raw.restype = c_int

    gnutls_openpgp_privkey_export_subkey_rsa_raw = libgnutls.gnutls_openpgp_privkey_export_subkey_rsa_raw
    gnutls_openpgp_privkey_export_subkey_rsa_raw.argtypes = [gnutls_openpgp_privkey_t, c_uint, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_openpgp_privkey_export_subkey_rsa_raw.restype = c_int

    gnutls_openpgp_privkey_get_fingerprint = libgnutls.gnutls_openpgp_privkey_get_fingerprint
    gnutls_openpgp_privkey_get_fingerprint.argtypes = [gnutls_openpgp_privkey_t, c_void_p, POINTER(size_t)]
    gnutls_openpgp_privkey_get_fingerprint.restype = c_int

    gnutls_openpgp_privkey_get_key_id = libgnutls.gnutls_openpgp_privkey_get_key_id
    gnutls_openpgp_privkey_get_key_id.argtypes = [gnutls_openpgp_privkey_t, POINTER(c_ubyte)]
    gnutls_openpgp_privkey_get_key_id.restype = c_int

    gnutls_openpgp_privkey_get_pk_algorithm = libgnutls.gnutls_openpgp_privkey_get_pk_algorithm
    gnutls_openpgp_privkey_get_pk_algorithm.argtypes = [gnutls_openpgp_privkey_t, POINTER(c_uint)]
    gnutls_openpgp_privkey_get_pk_algorithm.restype = gnutls_pk_algorithm_t

    gnutls_openpgp_privkey_get_preferred_key_id = libgnutls.gnutls_openpgp_privkey_get_preferred_key_id
    gnutls_openpgp_privkey_get_preferred_key_id.argtypes = [gnutls_openpgp_privkey_t, POINTER(c_ubyte)]
    gnutls_openpgp_privkey_get_preferred_key_id.restype = c_int

    gnutls_openpgp_privkey_get_revoked_status = libgnutls.gnutls_openpgp_privkey_get_revoked_status
    gnutls_openpgp_privkey_get_revoked_status.argtypes = [gnutls_openpgp_privkey_t]
    gnutls_openpgp_privkey_get_revoked_status.restype = c_int

    gnutls_openpgp_privkey_get_subkey_count = libgnutls.gnutls_openpgp_privkey_get_subkey_count
    gnutls_openpgp_privkey_get_subkey_count.argtypes = [gnutls_openpgp_privkey_t]
    gnutls_openpgp_privkey_get_subkey_count.restype = c_int

    gnutls_openpgp_privkey_get_subkey_creation_time = libgnutls.gnutls_openpgp_privkey_get_subkey_creation_time
    gnutls_openpgp_privkey_get_subkey_creation_time.argtypes = [gnutls_openpgp_privkey_t, c_uint]
    gnutls_openpgp_privkey_get_subkey_creation_time.restype = time_t
    gnutls_openpgp_privkey_get_subkey_creation_time.errmsg = "cannot get OpenPGP subkey creation time"

    gnutls_openpgp_privkey_get_subkey_expiration_time = libgnutls.gnutls_openpgp_privkey_get_subkey_expiration_time
    gnutls_openpgp_privkey_get_subkey_expiration_time.argtypes = [gnutls_openpgp_privkey_t, c_uint]
    gnutls_openpgp_privkey_get_subkey_expiration_time.restype = time_t
    gnutls_openpgp_privkey_get_subkey_expiration_time.errmsg = "cannot get OpenPGP subkey expiration time"

    gnutls_openpgp_privkey_get_subkey_fingerprint = libgnutls.gnutls_openpgp_privkey_get_subkey_fingerprint
    gnutls_openpgp_privkey_get_subkey_fingerprint.argtypes = [gnutls_openpgp_privkey_t, c_uint, c_void_p, POINTER(size_t)]
    gnutls_openpgp_privkey_get_subkey_fingerprint.restype = c_int

    gnutls_openpgp_privkey_get_subkey_id = libgnutls.gnutls_openpgp_privkey_get_subkey_id
    gnutls_openpgp_privkey_get_subkey_id.argtypes = [gnutls_openpgp_privkey_t, c_uint, POINTER(c_ubyte)]
    gnutls_openpgp_privkey_get_subkey_id.restype = c_int

    gnutls_openpgp_privkey_get_subkey_idx = libgnutls.gnutls_openpgp_privkey_get_subkey_idx
    gnutls_openpgp_privkey_get_subkey_idx.argtypes = [gnutls_openpgp_privkey_t, POINTER(c_ubyte)]
    gnutls_openpgp_privkey_get_subkey_idx.restype = c_int

    gnutls_openpgp_privkey_get_subkey_pk_algorithm = libgnutls.gnutls_openpgp_privkey_get_subkey_pk_algorithm
    gnutls_openpgp_privkey_get_subkey_pk_algorithm.argtypes = [gnutls_openpgp_privkey_t, c_uint, POINTER(c_uint)]
    gnutls_openpgp_privkey_get_subkey_pk_algorithm.restype = gnutls_pk_algorithm_t

    gnutls_openpgp_privkey_get_subkey_revoked_status = libgnutls.gnutls_openpgp_privkey_get_subkey_revoked_status
    gnutls_openpgp_privkey_get_subkey_revoked_status.argtypes = [gnutls_openpgp_privkey_t, c_uint]
    gnutls_openpgp_privkey_get_subkey_revoked_status.restype = c_int

    gnutls_openpgp_privkey_import = libgnutls.gnutls_openpgp_privkey_import
    gnutls_openpgp_privkey_import.argtypes = [gnutls_openpgp_privkey_t, POINTER(gnutls_datum_t), gnutls_openpgp_crt_fmt_t, c_char_p, c_uint]
    gnutls_openpgp_privkey_import.restype = c_int

    gnutls_openpgp_privkey_init = libgnutls.gnutls_openpgp_privkey_init
    gnutls_openpgp_privkey_init.argtypes = [POINTER(gnutls_openpgp_privkey_t)]
    gnutls_openpgp_privkey_init.restype = c_int

    gnutls_openpgp_privkey_set_preferred_key_id = libgnutls.gnutls_openpgp_privkey_set_preferred_key_id
    gnutls_openpgp_privkey_set_preferred_key_id.argtypes = [gnutls_openpgp_privkey_t, POINTER(c_ubyte)]
    gnutls_openpgp_privkey_set_preferred_key_id.restype = c_int

    gnutls_openpgp_send_cert = libgnutls.gnutls_openpgp_send_cert
    gnutls_openpgp_send_cert.argtypes = [gnutls_session_t, gnutls_openpgp_crt_status_t]
    gnutls_openpgp_send_cert.restype = None

    gnutls_openpgp_set_recv_key_function = libgnutls.gnutls_openpgp_set_recv_key_function
    gnutls_openpgp_set_recv_key_function.argtypes = [gnutls_session_t, gnutls_openpgp_recv_key_func]
    gnutls_openpgp_set_recv_key_function.restype = None

# The SRP related functions are not always present (some distributions do not compile SRP support into libgnutls)
#

try:
    gnutls_srp_allocate_client_credentials = libgnutls.gnutls_srp_allocate_client_credentials
except AttributeError:
    pass
else:
    gnutls_srp_allocate_client_credentials = libgnutls.gnutls_srp_allocate_client_credentials
    gnutls_srp_allocate_client_credentials.argtypes = [POINTER(gnutls_srp_client_credentials_t)]
    gnutls_srp_allocate_client_credentials.restype = c_int

    gnutls_srp_allocate_server_credentials = libgnutls.gnutls_srp_allocate_server_credentials
    gnutls_srp_allocate_server_credentials.argtypes = [POINTER(gnutls_srp_server_credentials_t)]
    gnutls_srp_allocate_server_credentials.restype = c_int

    gnutls_srp_base64_decode = libgnutls.gnutls_srp_base64_decode
    gnutls_srp_base64_decode.argtypes = [POINTER(gnutls_datum_t), c_char_p, POINTER(size_t)]
    gnutls_srp_base64_decode.restype = c_int

    gnutls_srp_base64_decode_alloc = libgnutls.gnutls_srp_base64_decode_alloc
    gnutls_srp_base64_decode_alloc.argtypes = [POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_srp_base64_decode_alloc.restype = c_int

    gnutls_srp_base64_encode = libgnutls.gnutls_srp_base64_encode
    gnutls_srp_base64_encode.argtypes = [POINTER(gnutls_datum_t), c_char_p, POINTER(size_t)]
    gnutls_srp_base64_encode.restype = c_int

    gnutls_srp_base64_encode_alloc = libgnutls.gnutls_srp_base64_encode_alloc
    gnutls_srp_base64_encode_alloc.argtypes = [POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_srp_base64_encode_alloc.restype = c_int

    gnutls_srp_free_client_credentials = libgnutls.gnutls_srp_free_client_credentials
    gnutls_srp_free_client_credentials.argtypes = [gnutls_srp_client_credentials_t]
    gnutls_srp_free_client_credentials.restype = None

    gnutls_srp_free_server_credentials = libgnutls.gnutls_srp_free_server_credentials
    gnutls_srp_free_server_credentials.argtypes = [gnutls_srp_server_credentials_t]
    gnutls_srp_free_server_credentials.restype = None

    gnutls_srp_server_get_username = libgnutls.gnutls_srp_server_get_username
    gnutls_srp_server_get_username.argtypes = [gnutls_session_t]
    gnutls_srp_server_get_username.restype = c_char_p

    gnutls_srp_set_client_credentials = libgnutls.gnutls_srp_set_client_credentials
    gnutls_srp_set_client_credentials.argtypes = [gnutls_srp_client_credentials_t, c_char_p, c_char_p]
    gnutls_srp_set_client_credentials.restype = c_int

    gnutls_srp_set_client_credentials_function = libgnutls.gnutls_srp_set_client_credentials_function
    gnutls_srp_set_client_credentials_function.argtypes = [gnutls_srp_client_credentials_t, gnutls_srp_client_credentials_function]
    gnutls_srp_set_client_credentials_function.restype = None

    gnutls_srp_set_server_credentials_file = libgnutls.gnutls_srp_set_server_credentials_file
    gnutls_srp_set_server_credentials_file.argtypes = [gnutls_srp_server_credentials_t, c_char_p, c_char_p]
    gnutls_srp_set_server_credentials_file.restype = c_int

    gnutls_srp_set_server_credentials_function = libgnutls.gnutls_srp_set_server_credentials_function
    gnutls_srp_set_server_credentials_function.argtypes = [gnutls_srp_server_credentials_t, gnutls_srp_server_credentials_function]
    gnutls_srp_set_server_credentials_function.restype = None

    gnutls_srp_verifier = libgnutls.gnutls_srp_verifier
    gnutls_srp_verifier.argtypes = [c_char_p, c_char_p, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
    gnutls_srp_verifier.restype = c_int


__all__ = sorted(name for name, obj in sys.modules[__name__].__dict__.iteritems() if name.startswith('gnutls_') and hasattr(obj, 'restype'))

