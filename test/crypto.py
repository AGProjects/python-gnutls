#!/usr/bin/python

import sys, os
script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
gnutls_path = os.path.realpath(os.path.join(script_path, '..'))
sys.path[0:0] = [gnutls_path]

from gnutls.crypto import *

certs_path = os.path.join(script_path, 'certs')

cert = X509Cert(open(certs_path + '/valid.crt').read())
key = PrivateKey(open(certs_path + '/valid.key').read())

ca = X509Cert(open(certs_path + '/ca.pem').read())
crl = X509CRL(open(certs_path + '/crl.pem').read())

print 'Cert subject: ', cert.subject
print 'Cert issuer:  ', cert.issuer


