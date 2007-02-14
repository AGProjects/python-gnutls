# Copyright (C) 2006-2007 Dan Pascu <dan@ag-projects.com>
#

__all__ = ['Error', 'GNUTLSError', 'GNUTLSException']

from gnutls.library.constants import *
from gnutls.library.types import *
from gnutls.library.functions import *

class Error(Exception): pass
class GNUTLSError(Error): pass

class GNUTLSException(object):
    @classmethod
    def check(cls, retcode):
        if retcode == 0:
            return
        elif retcode in (GNUTLS_E_MEMORY_ERROR, GNUTLS_E_SHORT_MEMORY_BUFFER):
            raise MemoryError(gnutls_strerror(retcode))
        else:
            raise GNUTLSError(gnutls_strerror(retcode))
