# Copyright (C) 2007 AG Projects. See LICENSE for details.
#

__version__ = '1.2.3'


# Fix threading issue with older ctypes. Prior to ctypes 1.0.3 string_at and
# wstring_at were not thread safe because they were declared using CFUNCTYPE
# which releases the GIL, but the functions call python C API functions that
# need the GIL to be acquired. See http://bugs.python.org/issue3554
#
import ctypes
if hasattr(ctypes, '_string_at') and isinstance(ctypes._string_at, ctypes._CFuncPtr) and not (ctypes._string_at._flags_ & ctypes._FUNCFLAG_PYTHONAPI):
    ctypes._string_at = ctypes.PYFUNCTYPE(ctypes.py_object, ctypes.c_void_p, ctypes.c_int)(ctypes._string_at_addr)
    if hasattr(ctypes, '_wstring_at'):
        ctypes._wstring_at = ctypes.PYFUNCTYPE(ctypes.py_object, ctypes.c_void_p, ctypes.c_int)(ctypes._wstring_at_addr)
del ctypes

