#!/usr/bin/python

import sys, os
script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
gnutls_path = os.path.realpath(os.path.join(script_path, '..'))
sys.path[0:0] = [gnutls_path]

import socket
from ctypes import *
from gnutls.library.constants import *
from gnutls.library.types import *
from gnutls.library.functions import *

certs_path = os.path.join(script_path, 'certs')

KEYFILE  = certs_path + "/valid.key"
CERTFILE = certs_path + "/valid.crt"
CAFILE   = certs_path + "/ca.pem"
CRLFILE  = certs_path + "/crl.pem"

PORT = 10000

DH_BITS = 1024

x509_cred = gnutls_certificate_credentials_t()
dh_params = gnutls_dh_params_t()

def generate_dh_params(dh_params):
    gnutls_dh_params_init(byref(dh_params))
    gnutls_dh_params_generate2(dh_params, DH_BITS)

def make_tls_session(x509_cred):
    session = gnutls_session_t()
    gnutls_init(byref(session), GNUTLS_SERVER)
    gnutls_set_default_priority(session)
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred)
    gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST)
    gnutls_dh_set_prime_bits(session, DH_BITS)
    return session

gnutls_certificate_allocate_credentials(byref(x509_cred))
gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM)
gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM)
#gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE, GNUTLS_X509_FMT_PEM)

generate_dh_params(dh_params)
gnutls_certificate_set_dh_params(x509_cred, dh_params)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('0.0.0.0', PORT))
sock.listen(10)

print "Server started"

while True:
    session = make_tls_session(x509_cred)
    new_sock, addr = sock.accept()
    print "Got new connection from %s:%s" % addr
    fd = new_sock.fileno()
    gnutls_transport_set_ptr(session, fd)
    res = gnutls_handshake(session)
    if res < 0:
        new_sock.close()
        gnutls_deinit(session)
        print "GNU TLS error: %d: %s" % (res, gnutls_strerror(res))
        continue
    print "TLS handshake succesful"
    status = c_ulong()
    res = gnutls_certificate_verify_peers2(session, byref(status))
    if res < 0:
        print "Failed to verify cert: %d: %s" % (res, gnutls_strerror(res))
    else:
        status = status.value
        if status & GNUTLS_CERT_INVALID:
            print "Invalid certificate"
        elif status & GNUTLS_CERT_SIGNER_NOT_FOUND:
            print "Couldn't find cert signer"
        elif status & GNUTLS_CERT_REVOKED:
            print "Cert was revoked"
        else:
            print "Cert is ok"
    while True:
        buf = create_string_buffer(8192)
        ret = gnutls_record_recv(session, buf, 8192)
        if ret == 0:
            print "Peer has closed the session"
            break
        elif ret < 0:
            print "Error in reception: %d: %s" % (ret, gnutls_strerror(ret))
            break
        else:
            if buf.value.strip().lower() == 'quit':
                print "Got quit command, closing connection"
                break
            buf.value = buf.value.rstrip() + " ACK!\n"
            gnutls_record_send(session, buf, len(buf.value))
    gnutls_bye(session, GNUTLS_SHUT_WR)
    new_sock.close()
    gnutls_deinit(session)

