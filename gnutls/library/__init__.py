# Copyright (C) 2007-2010 AG Projects. See LICENSE for details.
#


__all__ = ['constants', 'errors', 'functions', 'types']


def get_system_name():
    import platform
    system = platform.system().lower()
    if system.startswith('cygwin'):
        system = 'cygwin'
    return system


def library_locations(version):
    import os

    system = get_system_name()
    if system == 'darwin':
        library_names = ['libgnutls.%d.dylib' % version]
        dynamic_loader_env_vars = ['DYLD_LIBRARY_PATH', 'LD_LIBRARY_PATH']
        additional_paths = ['/usr/local/lib', '/opt/local/lib', '/sw/lib']
    elif system == 'windows':
        library_names = ['libgnutls-%d.dll' % version]
        dynamic_loader_env_vars = ['PATH']
        additional_paths = ['.']
    elif system == 'cygwin':
        library_names = ['cyggnutls-%d.dll' % version]
        dynamic_loader_env_vars = ['LD_LIBRARY_PATH']
        additional_paths = ['/usr/bin']
    else:
        # Debian uses libgnutls-deb0.so.28, go figure
        library_names = ['libgnutls.so.%d' % version, 'libgnutls-deb0.so.%d' % version]
        dynamic_loader_env_vars = ['LD_LIBRARY_PATH']
        additional_paths = ['/usr/local/lib']
    for library_name in library_names:
        for path in (path for env_var in dynamic_loader_env_vars for path in os.environ.get(env_var, '').split(':') if os.path.isdir(path)):
            yield os.path.join(path, library_name)
        yield library_name
        for path in additional_paths:
            yield os.path.join(path, library_name)


def load_library(version):
    from ctypes import CDLL

    for library in library_locations(version):
        try:
            return CDLL(library)
        except OSError:
            pass
        else:
            break
    else:
        raise RuntimeError('cannot find libgnutls on this system')


libgnutls = load_library(version=28)
libgnutls.gnutls_global_init()


from gnutls.library import constants
from gnutls.library import errors
from gnutls.library import functions
from gnutls.library import types


__need_version__ = '3.1.4'

if functions.gnutls_check_version(__need_version__) is None:
    version = functions.gnutls_check_version(None)
    raise RuntimeError("Found GNUTLS library version %s, but at least version %s is required" % (version, __need_version__))


del get_system_name, library_locations, load_library

