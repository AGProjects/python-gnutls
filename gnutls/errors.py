# Copyright (C) 2007 AG Projects. See LICENSE for details.
#

"""GNUTLS errors"""

__all__ = ['Error', 'GNUTLSError', 'OperationWouldBlock', 'OperationInterrupted',
           'CertificateError', 'CertificateAuthorityError', 'CertificateSecurityError',
           'CertificateExpiredError', 'CertificateRevokedError', 'RequestedDataNotAvailable']

class Error(Exception): pass

class GNUTLSError(Error): pass
class OperationWouldBlock(GNUTLSError): pass
class OperationInterrupted(GNUTLSError): pass

class CertificateError(GNUTLSError): pass
class CertificateAuthorityError(CertificateError): pass
class CertificateSecurityError(CertificateError): pass
class CertificateExpiredError(CertificateError): pass
class CertificateRevokedError(CertificateError): pass

class RequestedDataNotAvailable(GNUTLSError): pass
