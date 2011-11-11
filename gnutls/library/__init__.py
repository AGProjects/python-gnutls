# Copyright (C) 2007-2010 AG Projects. See LICENSE for details.
#


__all__ = ['constants', 'errors', 'functions', 'types']


def get_system_name():
    import platform
    system = platform.system().lower()
    if system.startswith('cygwin'):
        system = 'cygwin'
    return system


def library_locations(name, version):
    import os

    system = get_system_name()
    if system == 'darwin':
        library_name = 'lib%s.%d.dylib' % (name, version)
        dynamic_loader_env_vars = ['DYLD_LIBRARY_PATH', 'LD_LIBRARY_PATH']
        additional_paths = ['/usr/local/lib', '/opt/local/lib', '/sw/lib']
    elif system == 'windows':
        library_name = 'lib%s-%d.dll' % (name, version)
        dynamic_loader_env_vars = ['PATH']
        additional_paths = ['.']
    elif system == 'cygwin':
        library_name = 'cyg%s-%d.dll' % (name, version)
        dynamic_loader_env_vars = ['LD_LIBRARY_PATH']
        additional_paths = ['/usr/bin']
    else:
        library_name = 'lib%s.so.%d' % (name, version)
        dynamic_loader_env_vars = ['LD_LIBRARY_PATH']
        additional_paths = ['/usr/local/lib']
    for path in (path for env_var in dynamic_loader_env_vars for path in os.environ.get(env_var, '').split(':') if os.path.isdir(path)):
        yield os.path.join(path, library_name)
    yield library_name
    for path in additional_paths:
        yield os.path.join(path, library_name)


def load_library(name, version):
    from ctypes import CDLL

    for library in library_locations(name, version):
        try:
            return CDLL(library)
        except OSError:
            pass
        else:
            break
    else:
        raise RuntimeError('cannot find lib%s on this system' % name)


def initialize_gcrypt():
    from ctypes import c_void_p
    from gnutls.library._init import gcrypt_thread_callbacks_ptr

    GCRYCTL_INIT_SECMEM = 24
    GCRYCTL_SUSPEND_SECMEM_WARN = 28
    GCRYCTL_RESUME_SECMEM_WARN  = 29
    GCRYCTL_DISABLE_SECMEM = 37
    GCRYCTL_SET_THREAD_CBS = 47
    GCRYCTL_INITIALIZATION_FINISHED = 38

    system = get_system_name()

    if system == 'windows':
        from ctypes import CDLL, FormatError, POINTER, byref, create_unicode_buffer, c_wchar_p, sizeof, windll
        from ctypes.wintypes import BOOL, DWORD, HANDLE, HMODULE

        GetCurrentProcess = windll.kernel32.GetCurrentProcess
        GetCurrentProcess.argtypes = []
        GetCurrentProcess.restype = HANDLE

        try:
            EnumProcessModules = windll.kernel32.EnumProcessModules
        except AttributeError:
            EnumProcessModules = windll.psapi.EnumProcessModules
        EnumProcessModules.argtypes = [HANDLE, POINTER(HMODULE), DWORD, POINTER(DWORD)]
        EnumProcessModules.restype = BOOL

        GetModuleFileName = windll.kernel32.GetModuleFileNameW
        GetModuleFileName.argtypes = [HMODULE, c_wchar_p, DWORD]
        GetModuleFileName.restype = DWORD

        module_handles = (HMODULE * 1024)()
        module_name = create_unicode_buffer(65536)
        needed = DWORD()

        if EnumProcessModules(GetCurrentProcess(), module_handles, sizeof(module_handles), byref(needed)):
            for i in xrange(needed.value / sizeof(HMODULE)):
                if GetModuleFileName(module_handles[i], module_name, len(module_name)) and 'libgcrypt' in module_name.value:
                    libgcrypt = CDLL(module_name.value)
                    break
            else:
                raise RuntimeError('cannot find libgcrypt among the loaded dlls')
        else:
            raise RuntimeError('cannot obtain the process modules: %s' % FormatError())
        gcry_control = libgcrypt.gcry_control
    elif system == 'cygwin':
        libgcrypt = load_library(name='gcrypt', version=11)
        gcry_control = libgcrypt.gcry_control
    else:
        gcry_control = libgnutls.gcry_control

    gcry_control(GCRYCTL_SET_THREAD_CBS, c_void_p(gcrypt_thread_callbacks_ptr))
    if system == 'cygwin':
        gcry_control(GCRYCTL_DISABLE_SECMEM, 0)
    else:
        gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN)
        gcry_control(GCRYCTL_INIT_SECMEM, 32768, 0)
        gcry_control(GCRYCTL_RESUME_SECMEM_WARN)
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0)



libgnutls = load_library(name='gnutls', version=26)
libgnutls_extra = load_library(name='gnutls-extra', version=26)

initialize_gcrypt()
libgnutls.gnutls_global_init()
libgnutls_extra.gnutls_global_init_extra()


from gnutls.library import constants
from gnutls.library import errors
from gnutls.library import functions
from gnutls.library import types


__need_version__ = '2.4.1'

if functions.gnutls_check_version(__need_version__) is None:
    version = functions.gnutls_check_version(None)
    raise RuntimeError("Found GNUTLS library version %s, but at least version %s is required" % (version, __need_version__))
if functions.gnutls_extra_check_version(__need_version__) is None:
    version = functions.gnutls_extra_check_version(None)
    raise RuntimeError("Found GNUTLS extra library version %s, but at least version %s is required" % (version, __need_version__))


del get_system_name, library_locations, load_library, initialize_gcrypt

