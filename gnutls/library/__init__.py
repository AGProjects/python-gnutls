# Copyright (C) 2007 AG Projects. See LICENSE for details.
#

from gnutls.library import _gnutls_init
from gnutls.library import constants
from gnutls.library import types
from gnutls.library import errors
from gnutls.library import functions

__need_version__ = '2.2.2'

if functions.gnutls_check_version(__need_version__) is None:
    version = functions.gnutls_check_version(None)
    raise RuntimeError("Found GNUTLS library version %s, but at least version %s is required" % (version, __need_version__))
if functions.gnutls_extra_check_version(__need_version__) is None:
    version = functions.gnutls_extra_check_version(None)
    raise RuntimeError("Found GNUTLS extra library version %s, but at least version %s is required" % (version, __need_version__))
