#!/usr/bin/python

"""Cryptographic examples using python-gnutls"""

import sys
import os

from gnutls.crypto import *

script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
certs_path = os.path.join(script_path, 'certs')

cert = X509Certificate(open(certs_path + '/valid.crt').read())
key = X509PrivateKey(open(certs_path + '/valid.key').read())
ca = X509Certificate(open(certs_path + '/ca.pem').read())
crl = X509CRL(open(certs_path + '/crl.pem').read())

print 'Cert subject:   ', cert.subject
print 'Cert issuer:    ', cert.issuer
print 'Cert serial:    ', cert.serial_number
print 'Certificate was revoked: ', crl.is_revoked(cert)
print ""

cert = X509Certificate(open(certs_path + '/revoked.crt').read())

print 'Cert subject:   ', cert.subject
print 'Cert issuer:    ', cert.issuer
print 'Cert serial:    ', cert.serial_number
print 'Certificate was revoked: ', crl.is_revoked(cert)
print ""
