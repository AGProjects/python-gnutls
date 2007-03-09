from ctypes import *
from gnutls.library.constants import gnutls_pk_algorithm_t
_libraries = {}
_libraries['libgnutls.so.13'] = CDLL('libgnutls.so.13')
STRING = c_char_p
from gnutls.library.constants import gnutls_sign_algorithm_t
from gnutls.library.types import gnutls_session_t
from gnutls.library.constants import gnutls_connection_end_t
from gnutls.library.constants import gnutls_close_request_t
from gnutls.library.constants import gnutls_alert_description_t
from gnutls.library.constants import gnutls_alert_level_t
from gnutls.library.constants import gnutls_cipher_algorithm_t
from gnutls.library.constants import gnutls_kx_algorithm_t
from gnutls.library.constants import gnutls_mac_algorithm_t
from gnutls.library.constants import gnutls_compression_method_t
from gnutls.library.constants import gnutls_certificate_type_t
from gnutls.library.constants import gnutls_handshake_description_t
from gnutls.library.types import ssize_t
from gnutls.library.constants import gnutls_server_name_type_t
from gnutls.library.constants import gnutls_protocol_t
from gnutls.library.types import gnutls_datum_t
from gnutls.library.types import gnutls_db_retr_func
from gnutls.library.types import gnutls_db_remove_func
from gnutls.library.types import gnutls_db_store_func
from gnutls.library.types import gnutls_datum_t
from gnutls.library.constants import gnutls_credentials_type_t
from gnutls.library.types import gnutls_anon_server_credentials_t
from gnutls.library.types import gnutls_dh_params_t
from gnutls.library.types import gnutls_params_function
from gnutls.library.types import gnutls_anon_client_credentials_t
from gnutls.library.types import gnutls_certificate_credentials_t
from gnutls.library.types import gnutls_rsa_params_t
from gnutls.library.constants import gnutls_x509_crt_fmt_t
from gnutls.library.types import gnutls_x509_crt_t
from gnutls.library.types import gnutls_x509_privkey_t
from gnutls.library.types import gnutls_x509_crl_t
from gnutls.library.types import gnutls_alloc_function
from gnutls.library.types import gnutls_is_secure_function
from gnutls.library.types import gnutls_realloc_function
from gnutls.library.types import gnutls_free_function
from gnutls.library.types import gnutls_log_func
from gnutls.library.types import gnutls_transport_ptr_t
from gnutls.library.types import gnutls_push_func
from gnutls.library.types import gnutls_pull_func
from gnutls.library.constants import gnutls_openpgp_key_status_t
from gnutls.library.constants import gnutls_digest_algorithm_t
from gnutls.library.types import gnutls_srp_client_credentials_t
from gnutls.library.types import gnutls_srp_server_credentials_t
from gnutls.library.types import gnutls_srp_server_credentials_function
from gnutls.library.types import gnutls_srp_client_credentials_function
from gnutls.library.types import gnutls_psk_client_credentials_t
from gnutls.library.types import gnutls_psk_server_credentials_t
from gnutls.library.types import gnutls_psk_server_credentials_function
from gnutls.library.types import gnutls_psk_client_credentials_function
from gnutls.library.types import gnutls_certificate_client_retrieve_function
from gnutls.library.types import gnutls_certificate_server_retrieve_function
from gnutls.library.constants import gnutls_certificate_request_t
from gnutls.library.constants import gnutls_x509_subject_alt_name_t
from gnutls.library.types import gnutls_pkcs7_t
from gnutls.library.types import gnutls_x509_crq_t


gnutls_pk_algorithm_get_name = _libraries['libgnutls.so.13'].gnutls_pk_algorithm_get_name
gnutls_pk_algorithm_get_name.restype = STRING
gnutls_pk_algorithm_get_name.argtypes = [gnutls_pk_algorithm_t]
gnutls_sign_algorithm_get_name = _libraries['libgnutls.so.13'].gnutls_sign_algorithm_get_name
gnutls_sign_algorithm_get_name.restype = STRING
gnutls_sign_algorithm_get_name.argtypes = [gnutls_sign_algorithm_t]
gnutls_init = _libraries['libgnutls.so.13'].gnutls_init
gnutls_init.restype = c_int
gnutls_init.argtypes = [POINTER(gnutls_session_t), gnutls_connection_end_t]
gnutls_deinit = _libraries['libgnutls.so.13'].gnutls_deinit
gnutls_deinit.restype = None
gnutls_deinit.argtypes = [gnutls_session_t]
gnutls_bye = _libraries['libgnutls.so.13'].gnutls_bye
gnutls_bye.restype = c_int
gnutls_bye.argtypes = [gnutls_session_t, gnutls_close_request_t]
gnutls_handshake = _libraries['libgnutls.so.13'].gnutls_handshake
gnutls_handshake.restype = c_int
gnutls_handshake.argtypes = [gnutls_session_t]
gnutls_rehandshake = _libraries['libgnutls.so.13'].gnutls_rehandshake
gnutls_rehandshake.restype = c_int
gnutls_rehandshake.argtypes = [gnutls_session_t]
gnutls_alert_get = _libraries['libgnutls.so.13'].gnutls_alert_get
gnutls_alert_get.restype = gnutls_alert_description_t
gnutls_alert_get.argtypes = [gnutls_session_t]
gnutls_alert_send = _libraries['libgnutls.so.13'].gnutls_alert_send
gnutls_alert_send.restype = c_int
gnutls_alert_send.argtypes = [gnutls_session_t, gnutls_alert_level_t, gnutls_alert_description_t]
gnutls_alert_send_appropriate = _libraries['libgnutls.so.13'].gnutls_alert_send_appropriate
gnutls_alert_send_appropriate.restype = c_int
gnutls_alert_send_appropriate.argtypes = [gnutls_session_t, c_int]
gnutls_alert_get_name = _libraries['libgnutls.so.13'].gnutls_alert_get_name
gnutls_alert_get_name.restype = STRING
gnutls_alert_get_name.argtypes = [gnutls_alert_description_t]
gnutls_cipher_get = _libraries['libgnutls.so.13'].gnutls_cipher_get
gnutls_cipher_get.restype = gnutls_cipher_algorithm_t
gnutls_cipher_get.argtypes = [gnutls_session_t]
gnutls_kx_get = _libraries['libgnutls.so.13'].gnutls_kx_get
gnutls_kx_get.restype = gnutls_kx_algorithm_t
gnutls_kx_get.argtypes = [gnutls_session_t]
gnutls_mac_get = _libraries['libgnutls.so.13'].gnutls_mac_get
gnutls_mac_get.restype = gnutls_mac_algorithm_t
gnutls_mac_get.argtypes = [gnutls_session_t]
gnutls_compression_get = _libraries['libgnutls.so.13'].gnutls_compression_get
gnutls_compression_get.restype = gnutls_compression_method_t
gnutls_compression_get.argtypes = [gnutls_session_t]
gnutls_certificate_type_get = _libraries['libgnutls.so.13'].gnutls_certificate_type_get
gnutls_certificate_type_get.restype = gnutls_certificate_type_t
gnutls_certificate_type_get.argtypes = [gnutls_session_t]
size_t = c_uint
gnutls_cipher_get_key_size = _libraries['libgnutls.so.13'].gnutls_cipher_get_key_size
gnutls_cipher_get_key_size.restype = size_t
gnutls_cipher_get_key_size.argtypes = [gnutls_cipher_algorithm_t]
gnutls_cipher_get_name = _libraries['libgnutls.so.13'].gnutls_cipher_get_name
gnutls_cipher_get_name.restype = STRING
gnutls_cipher_get_name.argtypes = [gnutls_cipher_algorithm_t]
gnutls_mac_get_name = _libraries['libgnutls.so.13'].gnutls_mac_get_name
gnutls_mac_get_name.restype = STRING
gnutls_mac_get_name.argtypes = [gnutls_mac_algorithm_t]
gnutls_compression_get_name = _libraries['libgnutls.so.13'].gnutls_compression_get_name
gnutls_compression_get_name.restype = STRING
gnutls_compression_get_name.argtypes = [gnutls_compression_method_t]
gnutls_kx_get_name = _libraries['libgnutls.so.13'].gnutls_kx_get_name
gnutls_kx_get_name.restype = STRING
gnutls_kx_get_name.argtypes = [gnutls_kx_algorithm_t]
gnutls_certificate_type_get_name = _libraries['libgnutls.so.13'].gnutls_certificate_type_get_name
gnutls_certificate_type_get_name.restype = STRING
gnutls_certificate_type_get_name.argtypes = [gnutls_certificate_type_t]
gnutls_error_is_fatal = _libraries['libgnutls.so.13'].gnutls_error_is_fatal
gnutls_error_is_fatal.restype = c_int
gnutls_error_is_fatal.argtypes = [c_int]
gnutls_error_to_alert = _libraries['libgnutls.so.13'].gnutls_error_to_alert
gnutls_error_to_alert.restype = c_int
gnutls_error_to_alert.argtypes = [c_int, POINTER(c_int)]
gnutls_perror = _libraries['libgnutls.so.13'].gnutls_perror
gnutls_perror.restype = None
gnutls_perror.argtypes = [c_int]
gnutls_strerror = _libraries['libgnutls.so.13'].gnutls_strerror
gnutls_strerror.restype = STRING
gnutls_strerror.argtypes = [c_int]
gnutls_handshake_set_private_extensions = _libraries['libgnutls.so.13'].gnutls_handshake_set_private_extensions
gnutls_handshake_set_private_extensions.restype = None
gnutls_handshake_set_private_extensions.argtypes = [gnutls_session_t, c_int]
gnutls_handshake_get_last_out = _libraries['libgnutls.so.13'].gnutls_handshake_get_last_out
gnutls_handshake_get_last_out.restype = gnutls_handshake_description_t
gnutls_handshake_get_last_out.argtypes = [gnutls_session_t]
gnutls_handshake_get_last_in = _libraries['libgnutls.so.13'].gnutls_handshake_get_last_in
gnutls_handshake_get_last_in.restype = gnutls_handshake_description_t
gnutls_handshake_get_last_in.argtypes = [gnutls_session_t]
gnutls_record_send = _libraries['libgnutls.so.13'].gnutls_record_send
gnutls_record_send.restype = ssize_t
gnutls_record_send.argtypes = [gnutls_session_t, c_void_p, size_t]
gnutls_record_recv = _libraries['libgnutls.so.13'].gnutls_record_recv
gnutls_record_recv.restype = ssize_t
gnutls_record_recv.argtypes = [gnutls_session_t, c_void_p, size_t]
gnutls_record_get_direction = _libraries['libgnutls.so.13'].gnutls_record_get_direction
gnutls_record_get_direction.restype = c_int
gnutls_record_get_direction.argtypes = [gnutls_session_t]
gnutls_record_get_max_size = _libraries['libgnutls.so.13'].gnutls_record_get_max_size
gnutls_record_get_max_size.restype = size_t
gnutls_record_get_max_size.argtypes = [gnutls_session_t]
gnutls_record_set_max_size = _libraries['libgnutls.so.13'].gnutls_record_set_max_size
gnutls_record_set_max_size.restype = ssize_t
gnutls_record_set_max_size.argtypes = [gnutls_session_t, size_t]
gnutls_record_check_pending = _libraries['libgnutls.so.13'].gnutls_record_check_pending
gnutls_record_check_pending.restype = size_t
gnutls_record_check_pending.argtypes = [gnutls_session_t]
gnutls_prf = _libraries['libgnutls.so.13'].gnutls_prf
gnutls_prf.restype = c_int
gnutls_prf.argtypes = [gnutls_session_t, size_t, STRING, c_int, size_t, STRING, size_t, STRING]
gnutls_prf_raw = _libraries['libgnutls.so.13'].gnutls_prf_raw
gnutls_prf_raw.restype = c_int
gnutls_prf_raw.argtypes = [gnutls_session_t, size_t, STRING, size_t, STRING, size_t, STRING]
gnutls_server_name_set = _libraries['libgnutls.so.13'].gnutls_server_name_set
gnutls_server_name_set.restype = c_int
gnutls_server_name_set.argtypes = [gnutls_session_t, gnutls_server_name_type_t, c_void_p, size_t]
gnutls_server_name_get = _libraries['libgnutls.so.13'].gnutls_server_name_get
gnutls_server_name_get.restype = c_int
gnutls_server_name_get.argtypes = [gnutls_session_t, c_void_p, POINTER(size_t), POINTER(c_uint), c_uint]
gnutls_cipher_set_priority = _libraries['libgnutls.so.13'].gnutls_cipher_set_priority
gnutls_cipher_set_priority.restype = c_int
gnutls_cipher_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_mac_set_priority = _libraries['libgnutls.so.13'].gnutls_mac_set_priority
gnutls_mac_set_priority.restype = c_int
gnutls_mac_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_compression_set_priority = _libraries['libgnutls.so.13'].gnutls_compression_set_priority
gnutls_compression_set_priority.restype = c_int
gnutls_compression_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_kx_set_priority = _libraries['libgnutls.so.13'].gnutls_kx_set_priority
gnutls_kx_set_priority.restype = c_int
gnutls_kx_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_protocol_set_priority = _libraries['libgnutls.so.13'].gnutls_protocol_set_priority
gnutls_protocol_set_priority.restype = c_int
gnutls_protocol_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_certificate_type_set_priority = _libraries['libgnutls.so.13'].gnutls_certificate_type_set_priority
gnutls_certificate_type_set_priority.restype = c_int
gnutls_certificate_type_set_priority.argtypes = [gnutls_session_t, POINTER(c_int)]
gnutls_set_default_priority = _libraries['libgnutls.so.13'].gnutls_set_default_priority
gnutls_set_default_priority.restype = c_int
gnutls_set_default_priority.argtypes = [gnutls_session_t]
gnutls_set_default_export_priority = _libraries['libgnutls.so.13'].gnutls_set_default_export_priority
gnutls_set_default_export_priority.restype = c_int
gnutls_set_default_export_priority.argtypes = [gnutls_session_t]
gnutls_cipher_suite_get_name = _libraries['libgnutls.so.13'].gnutls_cipher_suite_get_name
gnutls_cipher_suite_get_name.restype = STRING
gnutls_cipher_suite_get_name.argtypes = [gnutls_kx_algorithm_t, gnutls_cipher_algorithm_t, gnutls_mac_algorithm_t]
gnutls_protocol_get_version = _libraries['libgnutls.so.13'].gnutls_protocol_get_version
gnutls_protocol_get_version.restype = gnutls_protocol_t
gnutls_protocol_get_version.argtypes = [gnutls_session_t]
gnutls_protocol_get_name = _libraries['libgnutls.so.13'].gnutls_protocol_get_name
gnutls_protocol_get_name.restype = STRING
gnutls_protocol_get_name.argtypes = [gnutls_protocol_t]
gnutls_session_set_data = _libraries['libgnutls.so.13'].gnutls_session_set_data
gnutls_session_set_data.restype = c_int
gnutls_session_set_data.argtypes = [gnutls_session_t, c_void_p, size_t]
gnutls_session_get_data = _libraries['libgnutls.so.13'].gnutls_session_get_data
gnutls_session_get_data.restype = c_int
gnutls_session_get_data.argtypes = [gnutls_session_t, c_void_p, POINTER(size_t)]
gnutls_session_get_data2 = _libraries['libgnutls.so.13'].gnutls_session_get_data2
gnutls_session_get_data2.restype = c_int
gnutls_session_get_data2.argtypes = [gnutls_session_t, POINTER(gnutls_datum_t)]
gnutls_session_get_id = _libraries['libgnutls.so.13'].gnutls_session_get_id
gnutls_session_get_id.restype = c_int
gnutls_session_get_id.argtypes = [gnutls_session_t, c_void_p, POINTER(size_t)]
gnutls_session_get_server_random = _libraries['libgnutls.so.13'].gnutls_session_get_server_random
gnutls_session_get_server_random.restype = c_void_p
gnutls_session_get_server_random.argtypes = [gnutls_session_t]
gnutls_session_get_client_random = _libraries['libgnutls.so.13'].gnutls_session_get_client_random
gnutls_session_get_client_random.restype = c_void_p
gnutls_session_get_client_random.argtypes = [gnutls_session_t]
gnutls_session_get_master_secret = _libraries['libgnutls.so.13'].gnutls_session_get_master_secret
gnutls_session_get_master_secret.restype = c_void_p
gnutls_session_get_master_secret.argtypes = [gnutls_session_t]
gnutls_session_is_resumed = _libraries['libgnutls.so.13'].gnutls_session_is_resumed
gnutls_session_is_resumed.restype = c_int
gnutls_session_is_resumed.argtypes = [gnutls_session_t]
gnutls_db_set_cache_expiration = _libraries['libgnutls.so.13'].gnutls_db_set_cache_expiration
gnutls_db_set_cache_expiration.restype = None
gnutls_db_set_cache_expiration.argtypes = [gnutls_session_t, c_int]
gnutls_db_remove_session = _libraries['libgnutls.so.13'].gnutls_db_remove_session
gnutls_db_remove_session.restype = None
gnutls_db_remove_session.argtypes = [gnutls_session_t]
gnutls_db_set_retrieve_function = _libraries['libgnutls.so.13'].gnutls_db_set_retrieve_function
gnutls_db_set_retrieve_function.restype = None
gnutls_db_set_retrieve_function.argtypes = [gnutls_session_t, gnutls_db_retr_func]
gnutls_db_set_remove_function = _libraries['libgnutls.so.13'].gnutls_db_set_remove_function
gnutls_db_set_remove_function.restype = None
gnutls_db_set_remove_function.argtypes = [gnutls_session_t, gnutls_db_remove_func]
gnutls_db_set_store_function = _libraries['libgnutls.so.13'].gnutls_db_set_store_function
gnutls_db_set_store_function.restype = None
gnutls_db_set_store_function.argtypes = [gnutls_session_t, gnutls_db_store_func]
gnutls_db_set_ptr = _libraries['libgnutls.so.13'].gnutls_db_set_ptr
gnutls_db_set_ptr.restype = None
gnutls_db_set_ptr.argtypes = [gnutls_session_t, c_void_p]
gnutls_db_get_ptr = _libraries['libgnutls.so.13'].gnutls_db_get_ptr
gnutls_db_get_ptr.restype = c_void_p
gnutls_db_get_ptr.argtypes = [gnutls_session_t]
gnutls_db_check_entry = _libraries['libgnutls.so.13'].gnutls_db_check_entry
gnutls_db_check_entry.restype = c_int
gnutls_db_check_entry.argtypes = [gnutls_session_t, gnutls_datum_t]
gnutls_handshake_set_max_packet_length = _libraries['libgnutls.so.13'].gnutls_handshake_set_max_packet_length
gnutls_handshake_set_max_packet_length.restype = None
gnutls_handshake_set_max_packet_length.argtypes = [gnutls_session_t, size_t]
gnutls_check_version = _libraries['libgnutls.so.13'].gnutls_check_version
gnutls_check_version.restype = STRING
gnutls_check_version.argtypes = [STRING]
gnutls_credentials_clear = _libraries['libgnutls.so.13'].gnutls_credentials_clear
gnutls_credentials_clear.restype = None
gnutls_credentials_clear.argtypes = [gnutls_session_t]
gnutls_credentials_set = _libraries['libgnutls.so.13'].gnutls_credentials_set
gnutls_credentials_set.restype = c_int
gnutls_credentials_set.argtypes = [gnutls_session_t, gnutls_credentials_type_t, c_void_p]
gnutls_anon_free_server_credentials = _libraries['libgnutls.so.13'].gnutls_anon_free_server_credentials
gnutls_anon_free_server_credentials.restype = None
gnutls_anon_free_server_credentials.argtypes = [gnutls_anon_server_credentials_t]
gnutls_anon_allocate_server_credentials = _libraries['libgnutls.so.13'].gnutls_anon_allocate_server_credentials
gnutls_anon_allocate_server_credentials.restype = c_int
gnutls_anon_allocate_server_credentials.argtypes = [POINTER(gnutls_anon_server_credentials_t)]
gnutls_anon_set_server_dh_params = _libraries['libgnutls.so.13'].gnutls_anon_set_server_dh_params
gnutls_anon_set_server_dh_params.restype = None
gnutls_anon_set_server_dh_params.argtypes = [gnutls_anon_server_credentials_t, gnutls_dh_params_t]
gnutls_anon_set_server_params_function = _libraries['libgnutls.so.13'].gnutls_anon_set_server_params_function
gnutls_anon_set_server_params_function.restype = None
gnutls_anon_set_server_params_function.argtypes = [gnutls_anon_server_credentials_t, gnutls_params_function]
gnutls_anon_free_client_credentials = _libraries['libgnutls.so.13'].gnutls_anon_free_client_credentials
gnutls_anon_free_client_credentials.restype = None
gnutls_anon_free_client_credentials.argtypes = [gnutls_anon_client_credentials_t]
gnutls_anon_allocate_client_credentials = _libraries['libgnutls.so.13'].gnutls_anon_allocate_client_credentials
gnutls_anon_allocate_client_credentials.restype = c_int
gnutls_anon_allocate_client_credentials.argtypes = [POINTER(gnutls_anon_client_credentials_t)]
gnutls_certificate_free_credentials = _libraries['libgnutls.so.13'].gnutls_certificate_free_credentials
gnutls_certificate_free_credentials.restype = None
gnutls_certificate_free_credentials.argtypes = [gnutls_certificate_credentials_t]
gnutls_certificate_allocate_credentials = _libraries['libgnutls.so.13'].gnutls_certificate_allocate_credentials
gnutls_certificate_allocate_credentials.restype = c_int
gnutls_certificate_allocate_credentials.argtypes = [POINTER(gnutls_certificate_credentials_t)]
gnutls_certificate_free_keys = _libraries['libgnutls.so.13'].gnutls_certificate_free_keys
gnutls_certificate_free_keys.restype = None
gnutls_certificate_free_keys.argtypes = [gnutls_certificate_credentials_t]
gnutls_certificate_free_cas = _libraries['libgnutls.so.13'].gnutls_certificate_free_cas
gnutls_certificate_free_cas.restype = None
gnutls_certificate_free_cas.argtypes = [gnutls_certificate_credentials_t]
gnutls_certificate_free_ca_names = _libraries['libgnutls.so.13'].gnutls_certificate_free_ca_names
gnutls_certificate_free_ca_names.restype = None
gnutls_certificate_free_ca_names.argtypes = [gnutls_certificate_credentials_t]
gnutls_certificate_free_crls = _libraries['libgnutls.so.13'].gnutls_certificate_free_crls
gnutls_certificate_free_crls.restype = None
gnutls_certificate_free_crls.argtypes = [gnutls_certificate_credentials_t]
gnutls_certificate_set_dh_params = _libraries['libgnutls.so.13'].gnutls_certificate_set_dh_params
gnutls_certificate_set_dh_params.restype = None
gnutls_certificate_set_dh_params.argtypes = [gnutls_certificate_credentials_t, gnutls_dh_params_t]
gnutls_certificate_set_rsa_export_params = _libraries['libgnutls.so.13'].gnutls_certificate_set_rsa_export_params
gnutls_certificate_set_rsa_export_params.restype = None
gnutls_certificate_set_rsa_export_params.argtypes = [gnutls_certificate_credentials_t, gnutls_rsa_params_t]
gnutls_certificate_set_verify_flags = _libraries['libgnutls.so.13'].gnutls_certificate_set_verify_flags
gnutls_certificate_set_verify_flags.restype = None
gnutls_certificate_set_verify_flags.argtypes = [gnutls_certificate_credentials_t, c_uint]
gnutls_certificate_set_verify_limits = _libraries['libgnutls.so.13'].gnutls_certificate_set_verify_limits
gnutls_certificate_set_verify_limits.restype = None
gnutls_certificate_set_verify_limits.argtypes = [gnutls_certificate_credentials_t, c_uint, c_uint]
gnutls_certificate_set_x509_trust_file = _libraries['libgnutls.so.13'].gnutls_certificate_set_x509_trust_file
gnutls_certificate_set_x509_trust_file.restype = c_int
gnutls_certificate_set_x509_trust_file.argtypes = [gnutls_certificate_credentials_t, STRING, gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_trust_mem = _libraries['libgnutls.so.13'].gnutls_certificate_set_x509_trust_mem
gnutls_certificate_set_x509_trust_mem.restype = c_int
gnutls_certificate_set_x509_trust_mem.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_crl_file = _libraries['libgnutls.so.13'].gnutls_certificate_set_x509_crl_file
gnutls_certificate_set_x509_crl_file.restype = c_int
gnutls_certificate_set_x509_crl_file.argtypes = [gnutls_certificate_credentials_t, STRING, gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_crl_mem = _libraries['libgnutls.so.13'].gnutls_certificate_set_x509_crl_mem
gnutls_certificate_set_x509_crl_mem.restype = c_int
gnutls_certificate_set_x509_crl_mem.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_key_file = _libraries['libgnutls.so.13'].gnutls_certificate_set_x509_key_file
gnutls_certificate_set_x509_key_file.restype = c_int
gnutls_certificate_set_x509_key_file.argtypes = [gnutls_certificate_credentials_t, STRING, STRING, gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_key_mem = _libraries['libgnutls.so.13'].gnutls_certificate_set_x509_key_mem
gnutls_certificate_set_x509_key_mem.restype = c_int
gnutls_certificate_set_x509_key_mem.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_certificate_set_x509_simple_pkcs12_file = _libraries['libgnutls.so.13'].gnutls_certificate_set_x509_simple_pkcs12_file
gnutls_certificate_set_x509_simple_pkcs12_file.restype = c_int
gnutls_certificate_set_x509_simple_pkcs12_file.argtypes = [gnutls_certificate_credentials_t, STRING, gnutls_x509_crt_fmt_t, STRING]
gnutls_certificate_set_x509_key = _libraries['libgnutls.so.13'].gnutls_certificate_set_x509_key
gnutls_certificate_set_x509_key.restype = c_int
gnutls_certificate_set_x509_key.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_x509_crt_t), c_int, gnutls_x509_privkey_t]
gnutls_certificate_set_x509_trust = _libraries['libgnutls.so.13'].gnutls_certificate_set_x509_trust
gnutls_certificate_set_x509_trust.restype = c_int
gnutls_certificate_set_x509_trust.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_x509_crt_t), c_int]
gnutls_certificate_set_x509_crl = _libraries['libgnutls.so.13'].gnutls_certificate_set_x509_crl
gnutls_certificate_set_x509_crl.restype = c_int
gnutls_certificate_set_x509_crl.argtypes = [gnutls_certificate_credentials_t, POINTER(gnutls_x509_crl_t), c_int]
gnutls_global_init = _libraries['libgnutls.so.13'].gnutls_global_init
gnutls_global_init.restype = c_int
gnutls_global_init.argtypes = []
gnutls_global_deinit = _libraries['libgnutls.so.13'].gnutls_global_deinit
gnutls_global_deinit.restype = None
gnutls_global_deinit.argtypes = []
gnutls_global_set_mem_functions = _libraries['libgnutls.so.13'].gnutls_global_set_mem_functions
gnutls_global_set_mem_functions.restype = None
gnutls_global_set_mem_functions.argtypes = [gnutls_alloc_function, gnutls_alloc_function, gnutls_is_secure_function, gnutls_realloc_function, gnutls_free_function]
gnutls_global_set_log_function = _libraries['libgnutls.so.13'].gnutls_global_set_log_function
gnutls_global_set_log_function.restype = None
gnutls_global_set_log_function.argtypes = [gnutls_log_func]
gnutls_global_set_log_level = _libraries['libgnutls.so.13'].gnutls_global_set_log_level
gnutls_global_set_log_level.restype = None
gnutls_global_set_log_level.argtypes = [c_int]
gnutls_dh_params_init = _libraries['libgnutls.so.13'].gnutls_dh_params_init
gnutls_dh_params_init.restype = c_int
gnutls_dh_params_init.argtypes = [POINTER(gnutls_dh_params_t)]
gnutls_dh_params_deinit = _libraries['libgnutls.so.13'].gnutls_dh_params_deinit
gnutls_dh_params_deinit.restype = None
gnutls_dh_params_deinit.argtypes = [gnutls_dh_params_t]
gnutls_dh_params_import_raw = _libraries['libgnutls.so.13'].gnutls_dh_params_import_raw
gnutls_dh_params_import_raw.restype = c_int
gnutls_dh_params_import_raw.argtypes = [gnutls_dh_params_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_dh_params_import_pkcs3 = _libraries['libgnutls.so.13'].gnutls_dh_params_import_pkcs3
gnutls_dh_params_import_pkcs3.restype = c_int
gnutls_dh_params_import_pkcs3.argtypes = [gnutls_dh_params_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_dh_params_generate2 = _libraries['libgnutls.so.13'].gnutls_dh_params_generate2
gnutls_dh_params_generate2.restype = c_int
gnutls_dh_params_generate2.argtypes = [gnutls_dh_params_t, c_uint]
gnutls_dh_params_export_pkcs3 = _libraries['libgnutls.so.13'].gnutls_dh_params_export_pkcs3
gnutls_dh_params_export_pkcs3.restype = c_int
gnutls_dh_params_export_pkcs3.argtypes = [gnutls_dh_params_t, gnutls_x509_crt_fmt_t, POINTER(c_ubyte), POINTER(size_t)]
gnutls_dh_params_export_raw = _libraries['libgnutls.so.13'].gnutls_dh_params_export_raw
gnutls_dh_params_export_raw.restype = c_int
gnutls_dh_params_export_raw.argtypes = [gnutls_dh_params_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(c_uint)]
gnutls_dh_params_cpy = _libraries['libgnutls.so.13'].gnutls_dh_params_cpy
gnutls_dh_params_cpy.restype = c_int
gnutls_dh_params_cpy.argtypes = [gnutls_dh_params_t, gnutls_dh_params_t]
gnutls_rsa_params_init = _libraries['libgnutls.so.13'].gnutls_rsa_params_init
gnutls_rsa_params_init.restype = c_int
gnutls_rsa_params_init.argtypes = [POINTER(gnutls_rsa_params_t)]
gnutls_rsa_params_deinit = _libraries['libgnutls.so.13'].gnutls_rsa_params_deinit
gnutls_rsa_params_deinit.restype = None
gnutls_rsa_params_deinit.argtypes = [gnutls_rsa_params_t]
gnutls_rsa_params_cpy = _libraries['libgnutls.so.13'].gnutls_rsa_params_cpy
gnutls_rsa_params_cpy.restype = c_int
gnutls_rsa_params_cpy.argtypes = [gnutls_rsa_params_t, gnutls_rsa_params_t]
gnutls_rsa_params_import_raw = _libraries['libgnutls.so.13'].gnutls_rsa_params_import_raw
gnutls_rsa_params_import_raw.restype = c_int
gnutls_rsa_params_import_raw.argtypes = [gnutls_rsa_params_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_rsa_params_generate2 = _libraries['libgnutls.so.13'].gnutls_rsa_params_generate2
gnutls_rsa_params_generate2.restype = c_int
gnutls_rsa_params_generate2.argtypes = [gnutls_rsa_params_t, c_uint]
gnutls_rsa_params_export_raw = _libraries['libgnutls.so.13'].gnutls_rsa_params_export_raw
gnutls_rsa_params_export_raw.restype = c_int
gnutls_rsa_params_export_raw.argtypes = [gnutls_rsa_params_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(c_uint)]
gnutls_rsa_params_export_pkcs1 = _libraries['libgnutls.so.13'].gnutls_rsa_params_export_pkcs1
gnutls_rsa_params_export_pkcs1.restype = c_int
gnutls_rsa_params_export_pkcs1.argtypes = [gnutls_rsa_params_t, gnutls_x509_crt_fmt_t, POINTER(c_ubyte), POINTER(size_t)]
gnutls_rsa_params_import_pkcs1 = _libraries['libgnutls.so.13'].gnutls_rsa_params_import_pkcs1
gnutls_rsa_params_import_pkcs1.restype = c_int
gnutls_rsa_params_import_pkcs1.argtypes = [gnutls_rsa_params_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_transport_set_ptr = _libraries['libgnutls.so.13'].gnutls_transport_set_ptr
gnutls_transport_set_ptr.restype = None
gnutls_transport_set_ptr.argtypes = [gnutls_session_t, gnutls_transport_ptr_t]
gnutls_transport_set_ptr2 = _libraries['libgnutls.so.13'].gnutls_transport_set_ptr2
gnutls_transport_set_ptr2.restype = None
gnutls_transport_set_ptr2.argtypes = [gnutls_session_t, gnutls_transport_ptr_t, gnutls_transport_ptr_t]
gnutls_transport_get_ptr = _libraries['libgnutls.so.13'].gnutls_transport_get_ptr
gnutls_transport_get_ptr.restype = gnutls_transport_ptr_t
gnutls_transport_get_ptr.argtypes = [gnutls_session_t]
gnutls_transport_get_ptr2 = _libraries['libgnutls.so.13'].gnutls_transport_get_ptr2
gnutls_transport_get_ptr2.restype = None
gnutls_transport_get_ptr2.argtypes = [gnutls_session_t, POINTER(gnutls_transport_ptr_t), POINTER(gnutls_transport_ptr_t)]
gnutls_transport_set_lowat = _libraries['libgnutls.so.13'].gnutls_transport_set_lowat
gnutls_transport_set_lowat.restype = None
gnutls_transport_set_lowat.argtypes = [gnutls_session_t, c_int]
gnutls_transport_set_push_function = _libraries['libgnutls.so.13'].gnutls_transport_set_push_function
gnutls_transport_set_push_function.restype = None
gnutls_transport_set_push_function.argtypes = [gnutls_session_t, gnutls_push_func]
gnutls_transport_set_pull_function = _libraries['libgnutls.so.13'].gnutls_transport_set_pull_function
gnutls_transport_set_pull_function.restype = None
gnutls_transport_set_pull_function.argtypes = [gnutls_session_t, gnutls_pull_func]
gnutls_session_set_ptr = _libraries['libgnutls.so.13'].gnutls_session_set_ptr
gnutls_session_set_ptr.restype = None
gnutls_session_set_ptr.argtypes = [gnutls_session_t, c_void_p]
gnutls_session_get_ptr = _libraries['libgnutls.so.13'].gnutls_session_get_ptr
gnutls_session_get_ptr.restype = c_void_p
gnutls_session_get_ptr.argtypes = [gnutls_session_t]
gnutls_openpgp_send_key = _libraries['libgnutls.so.13'].gnutls_openpgp_send_key
gnutls_openpgp_send_key.restype = None
gnutls_openpgp_send_key.argtypes = [gnutls_session_t, gnutls_openpgp_key_status_t]
gnutls_fingerprint = _libraries['libgnutls.so.13'].gnutls_fingerprint
gnutls_fingerprint.restype = c_int
gnutls_fingerprint.argtypes = [gnutls_digest_algorithm_t, POINTER(gnutls_datum_t), c_void_p, POINTER(size_t)]
gnutls_srp_free_client_credentials = _libraries['libgnutls.so.13'].gnutls_srp_free_client_credentials
gnutls_srp_free_client_credentials.restype = None
gnutls_srp_free_client_credentials.argtypes = [gnutls_srp_client_credentials_t]
gnutls_srp_allocate_client_credentials = _libraries['libgnutls.so.13'].gnutls_srp_allocate_client_credentials
gnutls_srp_allocate_client_credentials.restype = c_int
gnutls_srp_allocate_client_credentials.argtypes = [POINTER(gnutls_srp_client_credentials_t)]
gnutls_srp_set_client_credentials = _libraries['libgnutls.so.13'].gnutls_srp_set_client_credentials
gnutls_srp_set_client_credentials.restype = c_int
gnutls_srp_set_client_credentials.argtypes = [gnutls_srp_client_credentials_t, STRING, STRING]
gnutls_srp_free_server_credentials = _libraries['libgnutls.so.13'].gnutls_srp_free_server_credentials
gnutls_srp_free_server_credentials.restype = None
gnutls_srp_free_server_credentials.argtypes = [gnutls_srp_server_credentials_t]
gnutls_srp_allocate_server_credentials = _libraries['libgnutls.so.13'].gnutls_srp_allocate_server_credentials
gnutls_srp_allocate_server_credentials.restype = c_int
gnutls_srp_allocate_server_credentials.argtypes = [POINTER(gnutls_srp_server_credentials_t)]
gnutls_srp_set_server_credentials_file = _libraries['libgnutls.so.13'].gnutls_srp_set_server_credentials_file
gnutls_srp_set_server_credentials_file.restype = c_int
gnutls_srp_set_server_credentials_file.argtypes = [gnutls_srp_server_credentials_t, STRING, STRING]
gnutls_srp_server_get_username = _libraries['libgnutls.so.13'].gnutls_srp_server_get_username
gnutls_srp_server_get_username.restype = STRING
gnutls_srp_server_get_username.argtypes = [gnutls_session_t]
gnutls_srp_verifier = _libraries['libgnutls.so.13'].gnutls_srp_verifier
gnutls_srp_verifier.restype = c_int
gnutls_srp_verifier.argtypes = [STRING, STRING, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_srp_set_server_credentials_function = _libraries['libgnutls.so.13'].gnutls_srp_set_server_credentials_function
gnutls_srp_set_server_credentials_function.restype = None
gnutls_srp_set_server_credentials_function.argtypes = [gnutls_srp_server_credentials_t, gnutls_srp_server_credentials_function]
gnutls_srp_set_client_credentials_function = _libraries['libgnutls.so.13'].gnutls_srp_set_client_credentials_function
gnutls_srp_set_client_credentials_function.restype = None
gnutls_srp_set_client_credentials_function.argtypes = [gnutls_srp_client_credentials_t, gnutls_srp_client_credentials_function]
gnutls_srp_base64_encode = _libraries['libgnutls.so.13'].gnutls_srp_base64_encode
gnutls_srp_base64_encode.restype = c_int
gnutls_srp_base64_encode.argtypes = [POINTER(gnutls_datum_t), STRING, POINTER(size_t)]
gnutls_srp_base64_encode_alloc = _libraries['libgnutls.so.13'].gnutls_srp_base64_encode_alloc
gnutls_srp_base64_encode_alloc.restype = c_int
gnutls_srp_base64_encode_alloc.argtypes = [POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_srp_base64_decode = _libraries['libgnutls.so.13'].gnutls_srp_base64_decode
gnutls_srp_base64_decode.restype = c_int
gnutls_srp_base64_decode.argtypes = [POINTER(gnutls_datum_t), STRING, POINTER(size_t)]
gnutls_srp_base64_decode_alloc = _libraries['libgnutls.so.13'].gnutls_srp_base64_decode_alloc
gnutls_srp_base64_decode_alloc.restype = c_int
gnutls_srp_base64_decode_alloc.argtypes = [POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_psk_free_client_credentials = _libraries['libgnutls.so.13'].gnutls_psk_free_client_credentials
gnutls_psk_free_client_credentials.restype = None
gnutls_psk_free_client_credentials.argtypes = [gnutls_psk_client_credentials_t]
gnutls_psk_allocate_client_credentials = _libraries['libgnutls.so.13'].gnutls_psk_allocate_client_credentials
gnutls_psk_allocate_client_credentials.restype = c_int
gnutls_psk_allocate_client_credentials.argtypes = [POINTER(gnutls_psk_client_credentials_t)]
gnutls_psk_set_client_credentials = _libraries['libgnutls.so.13'].gnutls_psk_set_client_credentials
gnutls_psk_set_client_credentials.restype = c_int
gnutls_psk_set_client_credentials.argtypes = [gnutls_psk_client_credentials_t, STRING, POINTER(gnutls_datum_t), c_uint]
gnutls_psk_free_server_credentials = _libraries['libgnutls.so.13'].gnutls_psk_free_server_credentials
gnutls_psk_free_server_credentials.restype = None
gnutls_psk_free_server_credentials.argtypes = [gnutls_psk_server_credentials_t]
gnutls_psk_allocate_server_credentials = _libraries['libgnutls.so.13'].gnutls_psk_allocate_server_credentials
gnutls_psk_allocate_server_credentials.restype = c_int
gnutls_psk_allocate_server_credentials.argtypes = [POINTER(gnutls_psk_server_credentials_t)]
gnutls_psk_set_server_credentials_file = _libraries['libgnutls.so.13'].gnutls_psk_set_server_credentials_file
gnutls_psk_set_server_credentials_file.restype = c_int
gnutls_psk_set_server_credentials_file.argtypes = [gnutls_psk_server_credentials_t, STRING]
gnutls_psk_server_get_username = _libraries['libgnutls.so.13'].gnutls_psk_server_get_username
gnutls_psk_server_get_username.restype = STRING
gnutls_psk_server_get_username.argtypes = [gnutls_session_t]
gnutls_psk_set_server_credentials_function = _libraries['libgnutls.so.13'].gnutls_psk_set_server_credentials_function
gnutls_psk_set_server_credentials_function.restype = None
gnutls_psk_set_server_credentials_function.argtypes = [gnutls_psk_server_credentials_t, gnutls_psk_server_credentials_function]
gnutls_psk_set_client_credentials_function = _libraries['libgnutls.so.13'].gnutls_psk_set_client_credentials_function
gnutls_psk_set_client_credentials_function.restype = None
gnutls_psk_set_client_credentials_function.argtypes = [gnutls_psk_client_credentials_t, gnutls_psk_client_credentials_function]
gnutls_hex_encode = _libraries['libgnutls.so.13'].gnutls_hex_encode
gnutls_hex_encode.restype = c_int
gnutls_hex_encode.argtypes = [POINTER(gnutls_datum_t), STRING, POINTER(size_t)]
gnutls_hex_decode = _libraries['libgnutls.so.13'].gnutls_hex_decode
gnutls_hex_decode.restype = c_int
gnutls_hex_decode.argtypes = [POINTER(gnutls_datum_t), STRING, POINTER(size_t)]
gnutls_psk_set_server_dh_params = _libraries['libgnutls.so.13'].gnutls_psk_set_server_dh_params
gnutls_psk_set_server_dh_params.restype = None
gnutls_psk_set_server_dh_params.argtypes = [gnutls_psk_server_credentials_t, gnutls_dh_params_t]
gnutls_psk_set_server_params_function = _libraries['libgnutls.so.13'].gnutls_psk_set_server_params_function
gnutls_psk_set_server_params_function.restype = None
gnutls_psk_set_server_params_function.argtypes = [gnutls_psk_server_credentials_t, gnutls_params_function]
gnutls_auth_get_type = _libraries['libgnutls.so.13'].gnutls_auth_get_type
gnutls_auth_get_type.restype = gnutls_credentials_type_t
gnutls_auth_get_type.argtypes = [gnutls_session_t]
gnutls_auth_server_get_type = _libraries['libgnutls.so.13'].gnutls_auth_server_get_type
gnutls_auth_server_get_type.restype = gnutls_credentials_type_t
gnutls_auth_server_get_type.argtypes = [gnutls_session_t]
gnutls_auth_client_get_type = _libraries['libgnutls.so.13'].gnutls_auth_client_get_type
gnutls_auth_client_get_type.restype = gnutls_credentials_type_t
gnutls_auth_client_get_type.argtypes = [gnutls_session_t]
gnutls_dh_set_prime_bits = _libraries['libgnutls.so.13'].gnutls_dh_set_prime_bits
gnutls_dh_set_prime_bits.restype = None
gnutls_dh_set_prime_bits.argtypes = [gnutls_session_t, c_uint]
gnutls_dh_get_secret_bits = _libraries['libgnutls.so.13'].gnutls_dh_get_secret_bits
gnutls_dh_get_secret_bits.restype = c_int
gnutls_dh_get_secret_bits.argtypes = [gnutls_session_t]
gnutls_dh_get_peers_public_bits = _libraries['libgnutls.so.13'].gnutls_dh_get_peers_public_bits
gnutls_dh_get_peers_public_bits.restype = c_int
gnutls_dh_get_peers_public_bits.argtypes = [gnutls_session_t]
gnutls_dh_get_prime_bits = _libraries['libgnutls.so.13'].gnutls_dh_get_prime_bits
gnutls_dh_get_prime_bits.restype = c_int
gnutls_dh_get_prime_bits.argtypes = [gnutls_session_t]
gnutls_dh_get_group = _libraries['libgnutls.so.13'].gnutls_dh_get_group
gnutls_dh_get_group.restype = c_int
gnutls_dh_get_group.argtypes = [gnutls_session_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_dh_get_pubkey = _libraries['libgnutls.so.13'].gnutls_dh_get_pubkey
gnutls_dh_get_pubkey.restype = c_int
gnutls_dh_get_pubkey.argtypes = [gnutls_session_t, POINTER(gnutls_datum_t)]
gnutls_rsa_export_get_pubkey = _libraries['libgnutls.so.13'].gnutls_rsa_export_get_pubkey
gnutls_rsa_export_get_pubkey.restype = c_int
gnutls_rsa_export_get_pubkey.argtypes = [gnutls_session_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_rsa_export_get_modulus_bits = _libraries['libgnutls.so.13'].gnutls_rsa_export_get_modulus_bits
gnutls_rsa_export_get_modulus_bits.restype = c_int
gnutls_rsa_export_get_modulus_bits.argtypes = [gnutls_session_t]
gnutls_certificate_client_set_retrieve_function = _libraries['libgnutls.so.13'].gnutls_certificate_client_set_retrieve_function
gnutls_certificate_client_set_retrieve_function.restype = None
gnutls_certificate_client_set_retrieve_function.argtypes = [gnutls_certificate_credentials_t, gnutls_certificate_client_retrieve_function]
gnutls_certificate_server_set_retrieve_function = _libraries['libgnutls.so.13'].gnutls_certificate_server_set_retrieve_function
gnutls_certificate_server_set_retrieve_function.restype = None
gnutls_certificate_server_set_retrieve_function.argtypes = [gnutls_certificate_credentials_t, gnutls_certificate_server_retrieve_function]
gnutls_certificate_server_set_request = _libraries['libgnutls.so.13'].gnutls_certificate_server_set_request
gnutls_certificate_server_set_request.restype = None
gnutls_certificate_server_set_request.argtypes = [gnutls_session_t, gnutls_certificate_request_t]
gnutls_certificate_get_peers = _libraries['libgnutls.so.13'].gnutls_certificate_get_peers
gnutls_certificate_get_peers.restype = POINTER(gnutls_datum_t)
gnutls_certificate_get_peers.argtypes = [gnutls_session_t, POINTER(c_uint)]
gnutls_certificate_get_ours = _libraries['libgnutls.so.13'].gnutls_certificate_get_ours
gnutls_certificate_get_ours.restype = POINTER(gnutls_datum_t)
gnutls_certificate_get_ours.argtypes = [gnutls_session_t]
__time_t = c_long
time_t = __time_t
gnutls_certificate_activation_time_peers = _libraries['libgnutls.so.13'].gnutls_certificate_activation_time_peers
gnutls_certificate_activation_time_peers.restype = time_t
gnutls_certificate_activation_time_peers.argtypes = [gnutls_session_t]
gnutls_certificate_expiration_time_peers = _libraries['libgnutls.so.13'].gnutls_certificate_expiration_time_peers
gnutls_certificate_expiration_time_peers.restype = time_t
gnutls_certificate_expiration_time_peers.argtypes = [gnutls_session_t]
gnutls_certificate_client_get_request_status = _libraries['libgnutls.so.13'].gnutls_certificate_client_get_request_status
gnutls_certificate_client_get_request_status.restype = c_int
gnutls_certificate_client_get_request_status.argtypes = [gnutls_session_t]
gnutls_certificate_verify_peers2 = _libraries['libgnutls.so.13'].gnutls_certificate_verify_peers2
gnutls_certificate_verify_peers2.restype = c_int
gnutls_certificate_verify_peers2.argtypes = [gnutls_session_t, POINTER(c_uint)]
gnutls_certificate_verify_peers = _libraries['libgnutls.so.13'].gnutls_certificate_verify_peers
gnutls_certificate_verify_peers.restype = c_int
gnutls_certificate_verify_peers.argtypes = [gnutls_session_t]
gnutls_pem_base64_encode = _libraries['libgnutls.so.13'].gnutls_pem_base64_encode
gnutls_pem_base64_encode.restype = c_int
gnutls_pem_base64_encode.argtypes = [STRING, POINTER(gnutls_datum_t), STRING, POINTER(size_t)]
gnutls_pem_base64_decode = _libraries['libgnutls.so.13'].gnutls_pem_base64_decode
gnutls_pem_base64_decode.restype = c_int
gnutls_pem_base64_decode.argtypes = [STRING, POINTER(gnutls_datum_t), POINTER(c_ubyte), POINTER(size_t)]
gnutls_pem_base64_encode_alloc = _libraries['libgnutls.so.13'].gnutls_pem_base64_encode_alloc
gnutls_pem_base64_encode_alloc.restype = c_int
gnutls_pem_base64_encode_alloc.argtypes = [STRING, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_pem_base64_decode_alloc = _libraries['libgnutls.so.13'].gnutls_pem_base64_decode_alloc
gnutls_pem_base64_decode_alloc.restype = c_int
gnutls_pem_base64_decode_alloc.argtypes = [STRING, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_certificate_set_params_function = _libraries['libgnutls.so.13'].gnutls_certificate_set_params_function
gnutls_certificate_set_params_function.restype = None
gnutls_certificate_set_params_function.argtypes = [gnutls_certificate_credentials_t, gnutls_params_function]
gnutls_anon_set_params_function = _libraries['libgnutls.so.13'].gnutls_anon_set_params_function
gnutls_anon_set_params_function.restype = None
gnutls_anon_set_params_function.argtypes = [gnutls_anon_server_credentials_t, gnutls_params_function]
gnutls_psk_set_params_function = _libraries['libgnutls.so.13'].gnutls_psk_set_params_function
gnutls_psk_set_params_function.restype = None
gnutls_psk_set_params_function.argtypes = [gnutls_psk_server_credentials_t, gnutls_params_function]
gnutls_x509_crt_init = _libraries['libgnutls.so.13'].gnutls_x509_crt_init
gnutls_x509_crt_init.restype = c_int
gnutls_x509_crt_init.argtypes = [POINTER(gnutls_x509_crt_t)]
gnutls_x509_crt_deinit = _libraries['libgnutls.so.13'].gnutls_x509_crt_deinit
gnutls_x509_crt_deinit.restype = None
gnutls_x509_crt_deinit.argtypes = [gnutls_x509_crt_t]
gnutls_x509_crt_import = _libraries['libgnutls.so.13'].gnutls_x509_crt_import
gnutls_x509_crt_import.restype = c_int
gnutls_x509_crt_import.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_x509_crt_list_import = _libraries['libgnutls.so.13'].gnutls_x509_crt_list_import
gnutls_x509_crt_list_import.restype = c_int
gnutls_x509_crt_list_import.argtypes = [POINTER(gnutls_x509_crt_t), POINTER(c_uint), POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t, c_uint]
gnutls_x509_crt_export = _libraries['libgnutls.so.13'].gnutls_x509_crt_export
gnutls_x509_crt_export.restype = c_int
gnutls_x509_crt_export.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_issuer_dn = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_issuer_dn
gnutls_x509_crt_get_issuer_dn.restype = c_int
gnutls_x509_crt_get_issuer_dn.argtypes = [gnutls_x509_crt_t, STRING, POINTER(size_t)]
gnutls_x509_crt_get_issuer_dn_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_issuer_dn_oid
gnutls_x509_crt_get_issuer_dn_oid.restype = c_int
gnutls_x509_crt_get_issuer_dn_oid.argtypes = [gnutls_x509_crt_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_issuer_dn_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_issuer_dn_by_oid
gnutls_x509_crt_get_issuer_dn_by_oid.restype = c_int
gnutls_x509_crt_get_issuer_dn_by_oid.argtypes = [gnutls_x509_crt_t, STRING, c_int, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_dn = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_dn
gnutls_x509_crt_get_dn.restype = c_int
gnutls_x509_crt_get_dn.argtypes = [gnutls_x509_crt_t, STRING, POINTER(size_t)]
gnutls_x509_crt_get_dn_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_dn_oid
gnutls_x509_crt_get_dn_oid.restype = c_int
gnutls_x509_crt_get_dn_oid.argtypes = [gnutls_x509_crt_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_dn_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_dn_by_oid
gnutls_x509_crt_get_dn_by_oid.restype = c_int
gnutls_x509_crt_get_dn_by_oid.argtypes = [gnutls_x509_crt_t, STRING, c_int, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_crt_check_hostname = _libraries['libgnutls.so.13'].gnutls_x509_crt_check_hostname
gnutls_x509_crt_check_hostname.restype = c_int
gnutls_x509_crt_check_hostname.argtypes = [gnutls_x509_crt_t, STRING]
gnutls_x509_crt_get_signature_algorithm = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_signature_algorithm
gnutls_x509_crt_get_signature_algorithm.restype = c_int
gnutls_x509_crt_get_signature_algorithm.argtypes = [gnutls_x509_crt_t]
gnutls_x509_crt_get_version = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_version
gnutls_x509_crt_get_version.restype = c_int
gnutls_x509_crt_get_version.argtypes = [gnutls_x509_crt_t]
gnutls_x509_crt_get_key_id = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_key_id
gnutls_x509_crt_get_key_id.restype = c_int
gnutls_x509_crt_get_key_id.argtypes = [gnutls_x509_crt_t, c_uint, POINTER(c_ubyte), POINTER(size_t)]
gnutls_x509_crt_set_authority_key_id = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_authority_key_id
gnutls_x509_crt_set_authority_key_id.restype = c_int
gnutls_x509_crt_set_authority_key_id.argtypes = [gnutls_x509_crt_t, c_void_p, size_t]
gnutls_x509_crt_get_authority_key_id = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_authority_key_id
gnutls_x509_crt_get_authority_key_id.restype = c_int
gnutls_x509_crt_get_authority_key_id.argtypes = [gnutls_x509_crt_t, c_void_p, POINTER(size_t), POINTER(c_uint)]
gnutls_x509_crt_get_subject_key_id = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_subject_key_id
gnutls_x509_crt_get_subject_key_id.restype = c_int
gnutls_x509_crt_get_subject_key_id.argtypes = [gnutls_x509_crt_t, c_void_p, POINTER(size_t), POINTER(c_uint)]
gnutls_x509_crt_get_crl_dist_points = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_crl_dist_points
gnutls_x509_crt_get_crl_dist_points.restype = c_int
gnutls_x509_crt_get_crl_dist_points.argtypes = [gnutls_x509_crt_t, c_uint, c_void_p, POINTER(size_t), POINTER(c_uint), POINTER(c_uint)]
gnutls_x509_crt_set_crl_dist_points = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_crl_dist_points
gnutls_x509_crt_set_crl_dist_points.restype = c_int
gnutls_x509_crt_set_crl_dist_points.argtypes = [gnutls_x509_crt_t, gnutls_x509_subject_alt_name_t, c_void_p, c_uint]
gnutls_x509_crt_cpy_crl_dist_points = _libraries['libgnutls.so.13'].gnutls_x509_crt_cpy_crl_dist_points
gnutls_x509_crt_cpy_crl_dist_points.restype = c_int
gnutls_x509_crt_cpy_crl_dist_points.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_t]
gnutls_x509_crt_get_activation_time = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_activation_time
gnutls_x509_crt_get_activation_time.restype = time_t
gnutls_x509_crt_get_activation_time.argtypes = [gnutls_x509_crt_t]
gnutls_x509_crt_get_expiration_time = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_expiration_time
gnutls_x509_crt_get_expiration_time.restype = time_t
gnutls_x509_crt_get_expiration_time.argtypes = [gnutls_x509_crt_t]
gnutls_x509_crt_get_serial = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_serial
gnutls_x509_crt_get_serial.restype = c_int
gnutls_x509_crt_get_serial.argtypes = [gnutls_x509_crt_t, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_pk_algorithm = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_pk_algorithm
gnutls_x509_crt_get_pk_algorithm.restype = c_int
gnutls_x509_crt_get_pk_algorithm.argtypes = [gnutls_x509_crt_t, POINTER(c_uint)]
gnutls_x509_crt_get_pk_rsa_raw = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_pk_rsa_raw
gnutls_x509_crt_get_pk_rsa_raw.restype = c_int
gnutls_x509_crt_get_pk_rsa_raw.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_crt_get_pk_dsa_raw = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_pk_dsa_raw
gnutls_x509_crt_get_pk_dsa_raw.restype = c_int
gnutls_x509_crt_get_pk_dsa_raw.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_crt_get_subject_alt_name = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_subject_alt_name
gnutls_x509_crt_get_subject_alt_name.restype = c_int
gnutls_x509_crt_get_subject_alt_name.argtypes = [gnutls_x509_crt_t, c_uint, c_void_p, POINTER(size_t), POINTER(c_uint)]
gnutls_x509_crt_get_ca_status = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_ca_status
gnutls_x509_crt_get_ca_status.restype = c_int
gnutls_x509_crt_get_ca_status.argtypes = [gnutls_x509_crt_t, POINTER(c_uint)]
gnutls_x509_crt_get_key_usage = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_key_usage
gnutls_x509_crt_get_key_usage.restype = c_int
gnutls_x509_crt_get_key_usage.argtypes = [gnutls_x509_crt_t, POINTER(c_uint), POINTER(c_uint)]
gnutls_x509_crt_set_key_usage = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_key_usage
gnutls_x509_crt_set_key_usage.restype = c_int
gnutls_x509_crt_set_key_usage.argtypes = [gnutls_x509_crt_t, c_uint]
gnutls_x509_dn_oid_known = _libraries['libgnutls.so.13'].gnutls_x509_dn_oid_known
gnutls_x509_dn_oid_known.restype = c_int
gnutls_x509_dn_oid_known.argtypes = [STRING]
gnutls_x509_crt_get_extension_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_extension_oid
gnutls_x509_crt_get_extension_oid.restype = c_int
gnutls_x509_crt_get_extension_oid.argtypes = [gnutls_x509_crt_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_extension_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_extension_by_oid
gnutls_x509_crt_get_extension_by_oid.restype = c_int
gnutls_x509_crt_get_extension_by_oid.argtypes = [gnutls_x509_crt_t, STRING, c_int, c_void_p, POINTER(size_t), POINTER(c_uint)]
gnutls_x509_crt_set_extension_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_extension_by_oid
gnutls_x509_crt_set_extension_by_oid.restype = c_int
gnutls_x509_crt_set_extension_by_oid.argtypes = [gnutls_x509_crt_t, STRING, c_void_p, size_t, c_uint]
gnutls_x509_crt_to_xml = _libraries['libgnutls.so.13'].gnutls_x509_crt_to_xml
gnutls_x509_crt_to_xml.restype = c_int
gnutls_x509_crt_to_xml.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_datum_t), c_int]
gnutls_x509_crt_set_dn_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_dn_by_oid
gnutls_x509_crt_set_dn_by_oid.restype = c_int
gnutls_x509_crt_set_dn_by_oid.argtypes = [gnutls_x509_crt_t, STRING, c_uint, c_void_p, c_uint]
gnutls_x509_crt_set_issuer_dn_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_issuer_dn_by_oid
gnutls_x509_crt_set_issuer_dn_by_oid.restype = c_int
gnutls_x509_crt_set_issuer_dn_by_oid.argtypes = [gnutls_x509_crt_t, STRING, c_uint, c_void_p, c_uint]
gnutls_x509_crt_set_version = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_version
gnutls_x509_crt_set_version.restype = c_int
gnutls_x509_crt_set_version.argtypes = [gnutls_x509_crt_t, c_uint]
gnutls_x509_crt_set_key = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_key
gnutls_x509_crt_set_key.restype = c_int
gnutls_x509_crt_set_key.argtypes = [gnutls_x509_crt_t, gnutls_x509_privkey_t]
gnutls_x509_crt_set_ca_status = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_ca_status
gnutls_x509_crt_set_ca_status.restype = c_int
gnutls_x509_crt_set_ca_status.argtypes = [gnutls_x509_crt_t, c_uint]
gnutls_x509_crt_set_subject_alternative_name = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_subject_alternative_name
gnutls_x509_crt_set_subject_alternative_name.restype = c_int
gnutls_x509_crt_set_subject_alternative_name.argtypes = [gnutls_x509_crt_t, gnutls_x509_subject_alt_name_t, STRING]
gnutls_x509_crt_sign = _libraries['libgnutls.so.13'].gnutls_x509_crt_sign
gnutls_x509_crt_sign.restype = c_int
gnutls_x509_crt_sign.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_t, gnutls_x509_privkey_t]
gnutls_x509_crt_sign2 = _libraries['libgnutls.so.13'].gnutls_x509_crt_sign2
gnutls_x509_crt_sign2.restype = c_int
gnutls_x509_crt_sign2.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_t, gnutls_x509_privkey_t, gnutls_digest_algorithm_t, c_uint]
gnutls_x509_crt_set_activation_time = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_activation_time
gnutls_x509_crt_set_activation_time.restype = c_int
gnutls_x509_crt_set_activation_time.argtypes = [gnutls_x509_crt_t, time_t]
gnutls_x509_crt_set_expiration_time = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_expiration_time
gnutls_x509_crt_set_expiration_time.restype = c_int
gnutls_x509_crt_set_expiration_time.argtypes = [gnutls_x509_crt_t, time_t]
gnutls_x509_crt_set_serial = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_serial
gnutls_x509_crt_set_serial.restype = c_int
gnutls_x509_crt_set_serial.argtypes = [gnutls_x509_crt_t, c_void_p, size_t]
gnutls_x509_crt_set_subject_key_id = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_subject_key_id
gnutls_x509_crt_set_subject_key_id.restype = c_int
gnutls_x509_crt_set_subject_key_id.argtypes = [gnutls_x509_crt_t, c_void_p, size_t]
gnutls_x509_rdn_get = _libraries['libgnutls.so.13'].gnutls_x509_rdn_get
gnutls_x509_rdn_get.restype = c_int
gnutls_x509_rdn_get.argtypes = [POINTER(gnutls_datum_t), STRING, POINTER(size_t)]
gnutls_x509_rdn_get_oid = _libraries['libgnutls.so.13'].gnutls_x509_rdn_get_oid
gnutls_x509_rdn_get_oid.restype = c_int
gnutls_x509_rdn_get_oid.argtypes = [POINTER(gnutls_datum_t), c_int, c_void_p, POINTER(size_t)]
gnutls_x509_rdn_get_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_rdn_get_by_oid
gnutls_x509_rdn_get_by_oid.restype = c_int
gnutls_x509_rdn_get_by_oid.argtypes = [POINTER(gnutls_datum_t), STRING, c_int, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_crl_init = _libraries['libgnutls.so.13'].gnutls_x509_crl_init
gnutls_x509_crl_init.restype = c_int
gnutls_x509_crl_init.argtypes = [POINTER(gnutls_x509_crl_t)]
gnutls_x509_crl_deinit = _libraries['libgnutls.so.13'].gnutls_x509_crl_deinit
gnutls_x509_crl_deinit.restype = None
gnutls_x509_crl_deinit.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_import = _libraries['libgnutls.so.13'].gnutls_x509_crl_import
gnutls_x509_crl_import.restype = c_int
gnutls_x509_crl_import.argtypes = [gnutls_x509_crl_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_x509_crl_export = _libraries['libgnutls.so.13'].gnutls_x509_crl_export
gnutls_x509_crl_export.restype = c_int
gnutls_x509_crl_export.argtypes = [gnutls_x509_crl_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_x509_crl_get_issuer_dn = _libraries['libgnutls.so.13'].gnutls_x509_crl_get_issuer_dn
gnutls_x509_crl_get_issuer_dn.restype = c_int
gnutls_x509_crl_get_issuer_dn.argtypes = [gnutls_x509_crl_t, STRING, POINTER(size_t)]
gnutls_x509_crl_get_issuer_dn_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crl_get_issuer_dn_by_oid
gnutls_x509_crl_get_issuer_dn_by_oid.restype = c_int
gnutls_x509_crl_get_issuer_dn_by_oid.argtypes = [gnutls_x509_crl_t, STRING, c_int, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_crl_get_dn_oid = _libraries['libgnutls.so.13'].gnutls_x509_crl_get_dn_oid
gnutls_x509_crl_get_dn_oid.restype = c_int
gnutls_x509_crl_get_dn_oid.argtypes = [gnutls_x509_crl_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crl_get_signature_algorithm = _libraries['libgnutls.so.13'].gnutls_x509_crl_get_signature_algorithm
gnutls_x509_crl_get_signature_algorithm.restype = c_int
gnutls_x509_crl_get_signature_algorithm.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_get_version = _libraries['libgnutls.so.13'].gnutls_x509_crl_get_version
gnutls_x509_crl_get_version.restype = c_int
gnutls_x509_crl_get_version.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_get_this_update = _libraries['libgnutls.so.13'].gnutls_x509_crl_get_this_update
gnutls_x509_crl_get_this_update.restype = time_t
gnutls_x509_crl_get_this_update.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_get_next_update = _libraries['libgnutls.so.13'].gnutls_x509_crl_get_next_update
gnutls_x509_crl_get_next_update.restype = time_t
gnutls_x509_crl_get_next_update.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_get_crt_count = _libraries['libgnutls.so.13'].gnutls_x509_crl_get_crt_count
gnutls_x509_crl_get_crt_count.restype = c_int
gnutls_x509_crl_get_crt_count.argtypes = [gnutls_x509_crl_t]
gnutls_x509_crl_get_crt_serial = _libraries['libgnutls.so.13'].gnutls_x509_crl_get_crt_serial
gnutls_x509_crl_get_crt_serial.restype = c_int
gnutls_x509_crl_get_crt_serial.argtypes = [gnutls_x509_crl_t, c_int, POINTER(c_ubyte), POINTER(size_t), POINTER(time_t)]
gnutls_x509_crl_check_issuer = _libraries['libgnutls.so.13'].gnutls_x509_crl_check_issuer
gnutls_x509_crl_check_issuer.restype = c_int
gnutls_x509_crl_check_issuer.argtypes = [gnutls_x509_crl_t, gnutls_x509_crt_t]
gnutls_x509_crl_set_version = _libraries['libgnutls.so.13'].gnutls_x509_crl_set_version
gnutls_x509_crl_set_version.restype = c_int
gnutls_x509_crl_set_version.argtypes = [gnutls_x509_crl_t, c_uint]
gnutls_x509_crl_sign = _libraries['libgnutls.so.13'].gnutls_x509_crl_sign
gnutls_x509_crl_sign.restype = c_int
gnutls_x509_crl_sign.argtypes = [gnutls_x509_crl_t, gnutls_x509_crt_t, gnutls_x509_privkey_t]
gnutls_x509_crl_sign2 = _libraries['libgnutls.so.13'].gnutls_x509_crl_sign2
gnutls_x509_crl_sign2.restype = c_int
gnutls_x509_crl_sign2.argtypes = [gnutls_x509_crl_t, gnutls_x509_crt_t, gnutls_x509_privkey_t, gnutls_digest_algorithm_t, c_uint]
gnutls_x509_crl_set_this_update = _libraries['libgnutls.so.13'].gnutls_x509_crl_set_this_update
gnutls_x509_crl_set_this_update.restype = c_int
gnutls_x509_crl_set_this_update.argtypes = [gnutls_x509_crl_t, time_t]
gnutls_x509_crl_set_next_update = _libraries['libgnutls.so.13'].gnutls_x509_crl_set_next_update
gnutls_x509_crl_set_next_update.restype = c_int
gnutls_x509_crl_set_next_update.argtypes = [gnutls_x509_crl_t, time_t]
gnutls_x509_crl_set_crt_serial = _libraries['libgnutls.so.13'].gnutls_x509_crl_set_crt_serial
gnutls_x509_crl_set_crt_serial.restype = c_int
gnutls_x509_crl_set_crt_serial.argtypes = [gnutls_x509_crl_t, c_void_p, size_t, time_t]
gnutls_x509_crl_set_crt = _libraries['libgnutls.so.13'].gnutls_x509_crl_set_crt
gnutls_x509_crl_set_crt.restype = c_int
gnutls_x509_crl_set_crt.argtypes = [gnutls_x509_crl_t, gnutls_x509_crt_t, time_t]
gnutls_pkcs7_init = _libraries['libgnutls.so.13'].gnutls_pkcs7_init
gnutls_pkcs7_init.restype = c_int
gnutls_pkcs7_init.argtypes = [POINTER(gnutls_pkcs7_t)]
gnutls_pkcs7_deinit = _libraries['libgnutls.so.13'].gnutls_pkcs7_deinit
gnutls_pkcs7_deinit.restype = None
gnutls_pkcs7_deinit.argtypes = [gnutls_pkcs7_t]
gnutls_pkcs7_import = _libraries['libgnutls.so.13'].gnutls_pkcs7_import
gnutls_pkcs7_import.restype = c_int
gnutls_pkcs7_import.argtypes = [gnutls_pkcs7_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_pkcs7_export = _libraries['libgnutls.so.13'].gnutls_pkcs7_export
gnutls_pkcs7_export.restype = c_int
gnutls_pkcs7_export.argtypes = [gnutls_pkcs7_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_pkcs7_get_crt_count = _libraries['libgnutls.so.13'].gnutls_pkcs7_get_crt_count
gnutls_pkcs7_get_crt_count.restype = c_int
gnutls_pkcs7_get_crt_count.argtypes = [gnutls_pkcs7_t]
gnutls_pkcs7_get_crt_raw = _libraries['libgnutls.so.13'].gnutls_pkcs7_get_crt_raw
gnutls_pkcs7_get_crt_raw.restype = c_int
gnutls_pkcs7_get_crt_raw.argtypes = [gnutls_pkcs7_t, c_int, c_void_p, POINTER(size_t)]
gnutls_pkcs7_set_crt_raw = _libraries['libgnutls.so.13'].gnutls_pkcs7_set_crt_raw
gnutls_pkcs7_set_crt_raw.restype = c_int
gnutls_pkcs7_set_crt_raw.argtypes = [gnutls_pkcs7_t, POINTER(gnutls_datum_t)]
gnutls_pkcs7_set_crt = _libraries['libgnutls.so.13'].gnutls_pkcs7_set_crt
gnutls_pkcs7_set_crt.restype = c_int
gnutls_pkcs7_set_crt.argtypes = [gnutls_pkcs7_t, gnutls_x509_crt_t]
gnutls_pkcs7_delete_crt = _libraries['libgnutls.so.13'].gnutls_pkcs7_delete_crt
gnutls_pkcs7_delete_crt.restype = c_int
gnutls_pkcs7_delete_crt.argtypes = [gnutls_pkcs7_t, c_int]
gnutls_pkcs7_get_crl_raw = _libraries['libgnutls.so.13'].gnutls_pkcs7_get_crl_raw
gnutls_pkcs7_get_crl_raw.restype = c_int
gnutls_pkcs7_get_crl_raw.argtypes = [gnutls_pkcs7_t, c_int, c_void_p, POINTER(size_t)]
gnutls_pkcs7_get_crl_count = _libraries['libgnutls.so.13'].gnutls_pkcs7_get_crl_count
gnutls_pkcs7_get_crl_count.restype = c_int
gnutls_pkcs7_get_crl_count.argtypes = [gnutls_pkcs7_t]
gnutls_pkcs7_set_crl_raw = _libraries['libgnutls.so.13'].gnutls_pkcs7_set_crl_raw
gnutls_pkcs7_set_crl_raw.restype = c_int
gnutls_pkcs7_set_crl_raw.argtypes = [gnutls_pkcs7_t, POINTER(gnutls_datum_t)]
gnutls_pkcs7_set_crl = _libraries['libgnutls.so.13'].gnutls_pkcs7_set_crl
gnutls_pkcs7_set_crl.restype = c_int
gnutls_pkcs7_set_crl.argtypes = [gnutls_pkcs7_t, gnutls_x509_crl_t]
gnutls_pkcs7_delete_crl = _libraries['libgnutls.so.13'].gnutls_pkcs7_delete_crl
gnutls_pkcs7_delete_crl.restype = c_int
gnutls_pkcs7_delete_crl.argtypes = [gnutls_pkcs7_t, c_int]
gnutls_x509_crt_check_issuer = _libraries['libgnutls.so.13'].gnutls_x509_crt_check_issuer
gnutls_x509_crt_check_issuer.restype = c_int
gnutls_x509_crt_check_issuer.argtypes = [gnutls_x509_crt_t, gnutls_x509_crt_t]
gnutls_x509_crt_list_verify = _libraries['libgnutls.so.13'].gnutls_x509_crt_list_verify
gnutls_x509_crt_list_verify.restype = c_int
gnutls_x509_crt_list_verify.argtypes = [POINTER(gnutls_x509_crt_t), c_int, POINTER(gnutls_x509_crt_t), c_int, POINTER(gnutls_x509_crl_t), c_int, c_uint, POINTER(c_uint)]
gnutls_x509_crt_verify = _libraries['libgnutls.so.13'].gnutls_x509_crt_verify
gnutls_x509_crt_verify.restype = c_int
gnutls_x509_crt_verify.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_x509_crt_t), c_int, c_uint, POINTER(c_uint)]
gnutls_x509_crl_verify = _libraries['libgnutls.so.13'].gnutls_x509_crl_verify
gnutls_x509_crl_verify.restype = c_int
gnutls_x509_crl_verify.argtypes = [gnutls_x509_crl_t, POINTER(gnutls_x509_crt_t), c_int, c_uint, POINTER(c_uint)]
gnutls_x509_crt_check_revocation = _libraries['libgnutls.so.13'].gnutls_x509_crt_check_revocation
gnutls_x509_crt_check_revocation.restype = c_int
gnutls_x509_crt_check_revocation.argtypes = [gnutls_x509_crt_t, POINTER(gnutls_x509_crl_t), c_int]
gnutls_x509_crt_get_fingerprint = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_fingerprint
gnutls_x509_crt_get_fingerprint.restype = c_int
gnutls_x509_crt_get_fingerprint.argtypes = [gnutls_x509_crt_t, gnutls_digest_algorithm_t, c_void_p, POINTER(size_t)]
gnutls_x509_crt_get_key_purpose_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_get_key_purpose_oid
gnutls_x509_crt_get_key_purpose_oid.restype = c_int
gnutls_x509_crt_get_key_purpose_oid.argtypes = [gnutls_x509_crt_t, c_int, c_void_p, POINTER(size_t), POINTER(c_uint)]
gnutls_x509_crt_set_key_purpose_oid = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_key_purpose_oid
gnutls_x509_crt_set_key_purpose_oid.restype = c_int
gnutls_x509_crt_set_key_purpose_oid.argtypes = [gnutls_x509_crt_t, c_void_p, c_uint]
gnutls_x509_privkey_init = _libraries['libgnutls.so.13'].gnutls_x509_privkey_init
gnutls_x509_privkey_init.restype = c_int
gnutls_x509_privkey_init.argtypes = [POINTER(gnutls_x509_privkey_t)]
gnutls_x509_privkey_deinit = _libraries['libgnutls.so.13'].gnutls_x509_privkey_deinit
gnutls_x509_privkey_deinit.restype = None
gnutls_x509_privkey_deinit.argtypes = [gnutls_x509_privkey_t]
gnutls_x509_privkey_cpy = _libraries['libgnutls.so.13'].gnutls_x509_privkey_cpy
gnutls_x509_privkey_cpy.restype = c_int
gnutls_x509_privkey_cpy.argtypes = [gnutls_x509_privkey_t, gnutls_x509_privkey_t]
gnutls_x509_privkey_import = _libraries['libgnutls.so.13'].gnutls_x509_privkey_import
gnutls_x509_privkey_import.restype = c_int
gnutls_x509_privkey_import.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_x509_privkey_import_pkcs8 = _libraries['libgnutls.so.13'].gnutls_x509_privkey_import_pkcs8
gnutls_x509_privkey_import_pkcs8.restype = c_int
gnutls_x509_privkey_import_pkcs8.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t, STRING, c_uint]
gnutls_x509_privkey_import_rsa_raw = _libraries['libgnutls.so.13'].gnutls_x509_privkey_import_rsa_raw
gnutls_x509_privkey_import_rsa_raw.restype = c_int
gnutls_x509_privkey_import_rsa_raw.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_privkey_fix = _libraries['libgnutls.so.13'].gnutls_x509_privkey_fix
gnutls_x509_privkey_fix.restype = c_int
gnutls_x509_privkey_fix.argtypes = [gnutls_x509_privkey_t]
gnutls_x509_privkey_export_dsa_raw = _libraries['libgnutls.so.13'].gnutls_x509_privkey_export_dsa_raw
gnutls_x509_privkey_export_dsa_raw.restype = c_int
gnutls_x509_privkey_export_dsa_raw.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_privkey_import_dsa_raw = _libraries['libgnutls.so.13'].gnutls_x509_privkey_import_dsa_raw
gnutls_x509_privkey_import_dsa_raw.restype = c_int
gnutls_x509_privkey_import_dsa_raw.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_privkey_get_pk_algorithm = _libraries['libgnutls.so.13'].gnutls_x509_privkey_get_pk_algorithm
gnutls_x509_privkey_get_pk_algorithm.restype = c_int
gnutls_x509_privkey_get_pk_algorithm.argtypes = [gnutls_x509_privkey_t]
gnutls_x509_privkey_get_key_id = _libraries['libgnutls.so.13'].gnutls_x509_privkey_get_key_id
gnutls_x509_privkey_get_key_id.restype = c_int
gnutls_x509_privkey_get_key_id.argtypes = [gnutls_x509_privkey_t, c_uint, POINTER(c_ubyte), POINTER(size_t)]
gnutls_x509_privkey_generate = _libraries['libgnutls.so.13'].gnutls_x509_privkey_generate
gnutls_x509_privkey_generate.restype = c_int
gnutls_x509_privkey_generate.argtypes = [gnutls_x509_privkey_t, gnutls_pk_algorithm_t, c_uint, c_uint]
gnutls_x509_privkey_export = _libraries['libgnutls.so.13'].gnutls_x509_privkey_export
gnutls_x509_privkey_export.restype = c_int
gnutls_x509_privkey_export.argtypes = [gnutls_x509_privkey_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_x509_privkey_export_pkcs8 = _libraries['libgnutls.so.13'].gnutls_x509_privkey_export_pkcs8
gnutls_x509_privkey_export_pkcs8.restype = c_int
gnutls_x509_privkey_export_pkcs8.argtypes = [gnutls_x509_privkey_t, gnutls_x509_crt_fmt_t, STRING, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_privkey_export_rsa_raw = _libraries['libgnutls.so.13'].gnutls_x509_privkey_export_rsa_raw
gnutls_x509_privkey_export_rsa_raw.restype = c_int
gnutls_x509_privkey_export_rsa_raw.argtypes = [gnutls_x509_privkey_t, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_privkey_sign_data = _libraries['libgnutls.so.13'].gnutls_x509_privkey_sign_data
gnutls_x509_privkey_sign_data.restype = c_int
gnutls_x509_privkey_sign_data.argtypes = [gnutls_x509_privkey_t, gnutls_digest_algorithm_t, c_uint, POINTER(gnutls_datum_t), c_void_p, POINTER(size_t)]
gnutls_x509_privkey_verify_data = _libraries['libgnutls.so.13'].gnutls_x509_privkey_verify_data
gnutls_x509_privkey_verify_data.restype = c_int
gnutls_x509_privkey_verify_data.argtypes = [gnutls_x509_privkey_t, c_uint, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_crt_verify_data = _libraries['libgnutls.so.13'].gnutls_x509_crt_verify_data
gnutls_x509_crt_verify_data.restype = c_int
gnutls_x509_crt_verify_data.argtypes = [gnutls_x509_crt_t, c_uint, POINTER(gnutls_datum_t), POINTER(gnutls_datum_t)]
gnutls_x509_crq_init = _libraries['libgnutls.so.13'].gnutls_x509_crq_init
gnutls_x509_crq_init.restype = c_int
gnutls_x509_crq_init.argtypes = [POINTER(gnutls_x509_crq_t)]
gnutls_x509_crq_deinit = _libraries['libgnutls.so.13'].gnutls_x509_crq_deinit
gnutls_x509_crq_deinit.restype = None
gnutls_x509_crq_deinit.argtypes = [gnutls_x509_crq_t]
gnutls_x509_crq_import = _libraries['libgnutls.so.13'].gnutls_x509_crq_import
gnutls_x509_crq_import.restype = c_int
gnutls_x509_crq_import.argtypes = [gnutls_x509_crq_t, POINTER(gnutls_datum_t), gnutls_x509_crt_fmt_t]
gnutls_x509_crq_get_pk_algorithm = _libraries['libgnutls.so.13'].gnutls_x509_crq_get_pk_algorithm
gnutls_x509_crq_get_pk_algorithm.restype = c_int
gnutls_x509_crq_get_pk_algorithm.argtypes = [gnutls_x509_crq_t, POINTER(c_uint)]
gnutls_x509_crq_get_dn = _libraries['libgnutls.so.13'].gnutls_x509_crq_get_dn
gnutls_x509_crq_get_dn.restype = c_int
gnutls_x509_crq_get_dn.argtypes = [gnutls_x509_crq_t, STRING, POINTER(size_t)]
gnutls_x509_crq_get_dn_oid = _libraries['libgnutls.so.13'].gnutls_x509_crq_get_dn_oid
gnutls_x509_crq_get_dn_oid.restype = c_int
gnutls_x509_crq_get_dn_oid.argtypes = [gnutls_x509_crq_t, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crq_get_dn_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crq_get_dn_by_oid
gnutls_x509_crq_get_dn_by_oid.restype = c_int
gnutls_x509_crq_get_dn_by_oid.argtypes = [gnutls_x509_crq_t, STRING, c_int, c_uint, c_void_p, POINTER(size_t)]
gnutls_x509_crq_set_dn_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crq_set_dn_by_oid
gnutls_x509_crq_set_dn_by_oid.restype = c_int
gnutls_x509_crq_set_dn_by_oid.argtypes = [gnutls_x509_crq_t, STRING, c_uint, c_void_p, c_uint]
gnutls_x509_crq_set_version = _libraries['libgnutls.so.13'].gnutls_x509_crq_set_version
gnutls_x509_crq_set_version.restype = c_int
gnutls_x509_crq_set_version.argtypes = [gnutls_x509_crq_t, c_uint]
gnutls_x509_crq_set_key = _libraries['libgnutls.so.13'].gnutls_x509_crq_set_key
gnutls_x509_crq_set_key.restype = c_int
gnutls_x509_crq_set_key.argtypes = [gnutls_x509_crq_t, gnutls_x509_privkey_t]
gnutls_x509_crq_sign2 = _libraries['libgnutls.so.13'].gnutls_x509_crq_sign2
gnutls_x509_crq_sign2.restype = c_int
gnutls_x509_crq_sign2.argtypes = [gnutls_x509_crq_t, gnutls_x509_privkey_t, gnutls_digest_algorithm_t, c_uint]
gnutls_x509_crq_sign = _libraries['libgnutls.so.13'].gnutls_x509_crq_sign
gnutls_x509_crq_sign.restype = c_int
gnutls_x509_crq_sign.argtypes = [gnutls_x509_crq_t, gnutls_x509_privkey_t]
gnutls_x509_crq_set_challenge_password = _libraries['libgnutls.so.13'].gnutls_x509_crq_set_challenge_password
gnutls_x509_crq_set_challenge_password.restype = c_int
gnutls_x509_crq_set_challenge_password.argtypes = [gnutls_x509_crq_t, STRING]
gnutls_x509_crq_get_challenge_password = _libraries['libgnutls.so.13'].gnutls_x509_crq_get_challenge_password
gnutls_x509_crq_get_challenge_password.restype = c_int
gnutls_x509_crq_get_challenge_password.argtypes = [gnutls_x509_crq_t, STRING, POINTER(size_t)]
gnutls_x509_crq_set_attribute_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crq_set_attribute_by_oid
gnutls_x509_crq_set_attribute_by_oid.restype = c_int
gnutls_x509_crq_set_attribute_by_oid.argtypes = [gnutls_x509_crq_t, STRING, c_void_p, size_t]
gnutls_x509_crq_get_attribute_by_oid = _libraries['libgnutls.so.13'].gnutls_x509_crq_get_attribute_by_oid
gnutls_x509_crq_get_attribute_by_oid.restype = c_int
gnutls_x509_crq_get_attribute_by_oid.argtypes = [gnutls_x509_crq_t, STRING, c_int, c_void_p, POINTER(size_t)]
gnutls_x509_crq_export = _libraries['libgnutls.so.13'].gnutls_x509_crq_export
gnutls_x509_crq_export.restype = c_int
gnutls_x509_crq_export.argtypes = [gnutls_x509_crq_t, gnutls_x509_crt_fmt_t, c_void_p, POINTER(size_t)]
gnutls_x509_crt_set_crq = _libraries['libgnutls.so.13'].gnutls_x509_crt_set_crq
gnutls_x509_crt_set_crq.restype = c_int
gnutls_x509_crt_set_crq.argtypes = [gnutls_x509_crt_t, gnutls_x509_crq_t]
__all__ = ['gnutls_set_default_export_priority',
           'gnutls_x509_crl_sign', 'gnutls_x509_crt_verify',
           'gnutls_certificate_activation_time_peers',
           'gnutls_transport_set_ptr',
           'gnutls_x509_crt_get_crl_dist_points',
           'gnutls_db_set_remove_function', 'gnutls_x509_crq_get_dn',
           'gnutls_x509_crt_set_dn_by_oid', 'gnutls_perror',
           'gnutls_compression_get',
           'gnutls_srp_set_client_credentials_function',
           'gnutls_x509_crl_import', 'gnutls_x509_crl_export',
           'size_t', 'gnutls_rsa_export_get_pubkey',
           'gnutls_pkcs7_set_crl', 'gnutls_x509_crl_sign2',
           'gnutls_certificate_set_x509_trust_file',
           'gnutls_x509_crt_check_hostname',
           'gnutls_x509_crt_get_extension_oid',
           'gnutls_x509_crl_get_issuer_dn',
           'gnutls_x509_crl_get_next_update',
           'gnutls_x509_crt_get_pk_rsa_raw', 'gnutls_dh_get_pubkey',
           'gnutls_rsa_params_generate2', 'gnutls_x509_rdn_get_oid',
           'gnutls_handshake_set_private_extensions',
           'gnutls_certificate_free_crls', 'gnutls_record_recv',
           'gnutls_cipher_get', 'gnutls_certificate_type_get',
           'gnutls_auth_server_get_type',
           'gnutls_x509_crt_get_ca_status',
           'gnutls_record_get_max_size', 'gnutls_cipher_get_key_size',
           'gnutls_x509_crt_get_dn_oid',
           'gnutls_certificate_set_x509_crl_file',
           'gnutls_transport_get_ptr', 'gnutls_server_name_get',
           'gnutls_db_check_entry', 'gnutls_rsa_params_import_pkcs1',
           'gnutls_x509_crl_set_this_update',
           'gnutls_x509_crt_set_expiration_time',
           'gnutls_x509_privkey_import_dsa_raw',
           'gnutls_certificate_server_set_retrieve_function',
           'gnutls_x509_crq_init', 'gnutls_rsa_params_export_raw',
           'gnutls_session_set_ptr', 'gnutls_bye',
           'gnutls_session_get_master_secret',
           'gnutls_x509_crt_deinit', 'gnutls_auth_client_get_type',
           'gnutls_session_get_client_random',
           'gnutls_srp_base64_encode', 'gnutls_pkcs7_export',
           'gnutls_x509_privkey_import_pkcs8', '__time_t',
           'gnutls_x509_crt_get_pk_algorithm',
           'gnutls_session_get_data', 'gnutls_x509_rdn_get_by_oid',
           'gnutls_db_get_ptr', 'gnutls_x509_crt_list_import',
           'gnutls_protocol_get_version', 'gnutls_pkcs7_import',
           'gnutls_pkcs7_get_crt_raw', 'gnutls_certificate_free_keys',
           'gnutls_x509_crl_set_crt', 'gnutls_fingerprint',
           'gnutls_x509_crt_set_key', 'gnutls_mac_set_priority',
           'gnutls_certificate_verify_peers2',
           'gnutls_x509_privkey_sign_data',
           'gnutls_x509_crt_get_extension_by_oid',
           'gnutls_srp_verifier', 'gnutls_x509_crl_deinit',
           'gnutls_x509_crl_get_this_update',
           'gnutls_srp_set_server_credentials_function',
           'gnutls_certificate_free_ca_names',
           'gnutls_error_is_fatal', 'gnutls_x509_crt_verify_data',
           'gnutls_certificate_client_set_retrieve_function',
           'gnutls_x509_crl_get_crt_serial', 'gnutls_error_to_alert',
           'gnutls_x509_crl_get_dn_oid',
           'gnutls_x509_privkey_get_key_id',
           'gnutls_pkcs7_get_crt_count',
           'gnutls_certificate_set_x509_crl',
           'gnutls_rsa_export_get_modulus_bits',
           'gnutls_certificate_server_set_request',
           'gnutls_certificate_set_x509_trust',
           'gnutls_certificate_set_x509_crl_mem',
           'gnutls_pkcs7_get_crl_count', 'gnutls_rsa_params_deinit',
           'gnutls_x509_crt_get_subject_key_id',
           'gnutls_cipher_get_name', 'gnutls_dh_params_export_raw',
           'gnutls_handshake', 'gnutls_x509_crt_set_crl_dist_points',
           'gnutls_dh_get_group', 'gnutls_global_set_log_function',
           'gnutls_x509_crt_set_extension_by_oid',
           'gnutls_psk_set_client_credentials_function',
           'gnutls_x509_privkey_get_pk_algorithm',
           'gnutls_psk_set_client_credentials',
           'gnutls_x509_crt_get_key_id',
           'gnutls_set_default_priority', 'gnutls_x509_crt_sign',
           'gnutls_hex_encode', 'gnutls_dh_params_cpy',
           'gnutls_pkcs7_deinit', 'gnutls_x509_crl_set_version',
           'gnutls_rsa_params_import_raw',
           'gnutls_certificate_set_verify_limits',
           'gnutls_handshake_get_last_in',
           'gnutls_x509_crl_set_crt_serial',
           'gnutls_x509_crt_set_activation_time',
           'gnutls_dh_set_prime_bits', 'gnutls_db_set_ptr',
           'gnutls_x509_crq_get_attribute_by_oid',
           'gnutls_x509_privkey_export_dsa_raw',
           'gnutls_mac_get_name', 'gnutls_psk_server_get_username',
           'gnutls_anon_free_server_credentials',
           'gnutls_credentials_clear', 'gnutls_dh_params_init',
           'gnutls_session_get_data2',
           'gnutls_x509_crt_get_dn_by_oid', 'gnutls_kx_get',
           'gnutls_session_set_data', 'gnutls_protocol_get_name',
           'gnutls_dh_params_generate2',
           'gnutls_srp_set_server_credentials_file',
           'gnutls_certificate_allocate_credentials',
           'gnutls_x509_crt_set_serial',
           'gnutls_x509_crq_set_challenge_password',
           'gnutls_certificate_get_ours', 'gnutls_pkcs7_delete_crl',
           'gnutls_rsa_params_init', 'gnutls_x509_privkey_init',
           'gnutls_x509_crt_init',
           'gnutls_certificate_set_x509_key_mem',
           'gnutls_x509_crt_set_key_purpose_oid',
           'gnutls_certificate_free_credentials',
           'gnutls_x509_crt_set_subject_key_id',
           'gnutls_session_get_server_random', 'gnutls_mac_get',
           'gnutls_x509_crq_set_version', 'gnutls_dh_params_deinit',
           'gnutls_x509_privkey_cpy', 'gnutls_record_get_direction',
           'gnutls_session_get_ptr', 'gnutls_x509_crt_list_verify',
           'gnutls_dh_get_secret_bits',
           'gnutls_x509_crt_get_expiration_time',
           'gnutls_global_deinit', 'gnutls_sign_algorithm_get_name',
           'gnutls_anon_allocate_client_credentials',
           'gnutls_x509_crt_export',
           'gnutls_psk_set_server_dh_params',
           'gnutls_certificate_get_peers',
           'gnutls_transport_set_pull_function',
           'gnutls_x509_crl_init', 'gnutls_record_send',
           'gnutls_psk_allocate_client_credentials',
           'gnutls_srp_set_client_credentials',
           'gnutls_pem_base64_encode',
           'gnutls_x509_crt_get_key_purpose_oid',
           'gnutls_handshake_set_max_packet_length',
           'gnutls_certificate_set_x509_key',
           'gnutls_x509_privkey_import_rsa_raw',
           'gnutls_x509_crl_get_crt_count',
           'gnutls_srp_base64_decode_alloc',
           'gnutls_x509_crq_set_key', 'gnutls_x509_crq_set_dn_by_oid',
           'gnutls_x509_crq_get_challenge_password',
           'gnutls_dh_params_import_pkcs3', 'gnutls_session_get_id',
           'gnutls_x509_crq_sign', 'gnutls_cipher_set_priority',
           'gnutls_pk_algorithm_get_name', 'gnutls_x509_crq_export',
           'gnutls_hex_decode', 'gnutls_global_set_log_level',
           'gnutls_x509_privkey_generate', 'gnutls_x509_rdn_get',
           'gnutls_psk_set_params_function',
           'gnutls_srp_base64_encode_alloc',
           'gnutls_x509_crt_check_issuer',
           'gnutls_db_set_store_function',
           'gnutls_x509_crl_set_next_update',
           'gnutls_pkcs7_get_crl_raw', 'gnutls_db_remove_session',
           'gnutls_handshake_get_last_out',
           'gnutls_psk_free_client_credentials',
           'gnutls_x509_crt_get_authority_key_id',
           'gnutls_x509_privkey_export_pkcs8',
           'gnutls_x509_privkey_deinit', 'gnutls_alert_get_name',
           'gnutls_record_set_max_size',
           'gnutls_alert_send_appropriate',
           'gnutls_anon_set_server_dh_params',
           'gnutls_certificate_set_rsa_export_params',
           'gnutls_x509_crt_get_issuer_dn',
           'gnutls_x509_crt_set_authority_key_id',
           'gnutls_x509_crt_get_key_usage',
           'gnutls_x509_crt_get_signature_algorithm',
           'gnutls_x509_privkey_export',
           'gnutls_cipher_suite_get_name',
           'gnutls_x509_crt_get_version', 'gnutls_pkcs7_set_crt_raw',
           'gnutls_pkcs7_delete_crt',
           'gnutls_certificate_type_get_name',
           'gnutls_x509_crt_set_crq', 'gnutls_x509_crl_get_version',
           'gnutls_auth_get_type', 'gnutls_x509_crq_get_dn_oid',
           'gnutls_x509_dn_oid_known',
           'gnutls_srp_free_client_credentials', 'gnutls_alert_send',
           'gnutls_x509_crt_get_pk_dsa_raw',
           'gnutls_srp_allocate_server_credentials',
           'gnutls_certificate_verify_peers',
           'gnutls_dh_get_peers_public_bits',
           'gnutls_dh_get_prime_bits', 'gnutls_certificate_free_cas',
           'gnutls_srp_free_server_credentials',
           'gnutls_x509_privkey_fix', 'gnutls_pkcs7_set_crt',
           'gnutls_kx_get_name', 'gnutls_credentials_set',
           'gnutls_alert_get', 'gnutls_pkcs7_init',
           'gnutls_psk_set_server_params_function',
           'gnutls_transport_set_ptr2', 'gnutls_server_name_set',
           'gnutls_x509_crt_set_issuer_dn_by_oid',
           'gnutls_x509_crl_check_issuer',
           'gnutls_x509_crl_get_signature_algorithm',
           'gnutls_kx_set_priority',
           'gnutls_transport_set_push_function', 'gnutls_prf_raw',
           'gnutls_anon_allocate_server_credentials',
           'gnutls_x509_crt_get_issuer_dn_by_oid',
           'gnutls_rehandshake',
           'gnutls_x509_crt_cpy_crl_dist_points',
           'gnutls_x509_crt_set_subject_alternative_name',
           'gnutls_psk_set_server_credentials_file',
           'gnutls_session_is_resumed', 'gnutls_pem_base64_decode',
           'gnutls_srp_base64_decode',
           'gnutls_certificate_set_x509_trust_mem',
           'gnutls_x509_crt_set_version',
           'gnutls_dh_params_export_pkcs3',
           'gnutls_x509_crq_get_pk_algorithm', 'gnutls_global_init',
           'gnutls_psk_set_server_credentials_function',
           'gnutls_anon_set_params_function',
           'gnutls_x509_crq_deinit',
           'gnutls_certificate_set_params_function',
           'gnutls_x509_crt_get_fingerprint',
           'gnutls_x509_privkey_verify_data',
           'gnutls_dh_params_import_raw',
           'gnutls_srp_allocate_client_credentials',
           'gnutls_x509_crl_get_issuer_dn_by_oid', 'gnutls_deinit',
           'gnutls_global_set_mem_functions',
           'gnutls_x509_crt_check_revocation',
           'gnutls_compression_set_priority',
           'gnutls_x509_crt_import', 'gnutls_x509_crt_set_key_usage',
           'gnutls_x509_crt_get_activation_time',
           'gnutls_db_set_retrieve_function',
           'gnutls_x509_privkey_import',
           'gnutls_x509_crt_get_subject_alt_name', 'time_t',
           'gnutls_transport_set_lowat',
           'gnutls_anon_set_server_params_function',
           'gnutls_certificate_set_x509_simple_pkcs12_file',
           'gnutls_protocol_set_priority', 'gnutls_x509_crt_sign2',
           'gnutls_x509_privkey_export_rsa_raw',
           'gnutls_x509_crl_verify', 'gnutls_db_set_cache_expiration',
           'gnutls_x509_crt_set_ca_status', 'gnutls_rsa_params_cpy',
           'gnutls_strerror', 'gnutls_x509_crq_sign2',
           'gnutls_x509_crt_get_dn', 'gnutls_check_version',
           'gnutls_certificate_client_get_request_status',
           'gnutls_psk_allocate_server_credentials',
           'gnutls_certificate_set_verify_flags',
           'gnutls_x509_crt_to_xml', 'gnutls_rsa_params_export_pkcs1',
           'gnutls_prf', 'gnutls_transport_get_ptr2',
           'gnutls_srp_server_get_username',
           'gnutls_psk_free_server_credentials',
           'gnutls_x509_crt_get_serial',
           'gnutls_certificate_type_set_priority',
           'gnutls_pkcs7_set_crl_raw',
           'gnutls_x509_crt_get_issuer_dn_oid',
           'gnutls_record_check_pending',
           'gnutls_compression_get_name',
           'gnutls_x509_crq_set_attribute_by_oid',
           'gnutls_certificate_expiration_time_peers',
           'gnutls_pem_base64_decode_alloc',
           'gnutls_x509_crq_get_dn_by_oid', 'gnutls_x509_crq_import',
           'gnutls_openpgp_send_key',
           'gnutls_anon_free_client_credentials',
           'gnutls_certificate_set_x509_key_file',
           'gnutls_pem_base64_encode_alloc',
           'gnutls_certificate_set_dh_params', 'gnutls_init']
