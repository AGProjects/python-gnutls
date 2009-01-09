#!/usr/bin/env python

from distutils.core import setup, Extension
from gnutls import __version__
import subprocess
import sys
import platform
import os

# Get the title and description from README
import re
readme = open('README').read()
title, intro = re.findall(r'^\s*([^\n]+)\s+(.*)$', readme, re.DOTALL)[0]

# Get GNUTLS library version and compile/link options
def get_options():
    GNUTLS_CONF = 'libgnutls-config'
    GNUTLS_EXTRA_CONF = 'libgnutls-extra-config'
    library_init = open('gnutls/library/__init__.py').read()
    gnutls_version_req = [int(num) for num in re.findall(r"__need_version__ = '(\d)\.(\d)\.(\d)'", library_init)[0]]
    try:
        sub = subprocess.Popen([GNUTLS_CONF, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        # return some sane defaults if libgnutls-config is not available
        return [], [], ['gcrypt', 'gnutls', 'gnutls-extra']
    sub.wait()
    gnutls_version = [int(num) for num in sub.stdout.read().strip().split(".")]
    # check the returned version number against the required version in the debian/control file
    if not gnutls_version >= gnutls_version_req:
        print 'python-gnutls requires version %d.%d.%d of libgnutls (found %d.%d.%d).' % tuple(gnutls_version_req + gnutls_version)
        sys.exit()
    sub = subprocess.Popen([GNUTLS_CONF, '--libs', '--cflags'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sub.wait()
    gnutls_options = re.findall('-(.*?)[\n ]', sub.stdout.read())
    sub = subprocess.Popen([GNUTLS_EXTRA_CONF, '--libs', '--cflags'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sub.wait()
    gnutls_extra_options = re.findall('-(.*?)[\n ]', sub.stdout.read())
    # filter out the unique options from the output of both scripts
    include_dirs = list(set(option[1:] for option in gnutls_options + gnutls_extra_options if option.startswith('I')))
    library_dirs = list(set(option[1:] for option in gnutls_options + gnutls_extra_options if option.startswith('L')))
    libraries = list(set(option[1:] for option in gnutls_options + gnutls_extra_options if option.startswith('l')))
    # on OS-X, replace the library names in gnutls/library/functions.py and include the full path to it
    if platform.system() == "Darwin":
        functions_py = open('gnutls/library/functions.py').read()
        if gnutls_options.index('lgnutls') > 0:
            gnutls_dir = gnutls_options[gnutls_options.index('lgnutls') - 1]
            if gnutls_dir.startswith('L'):
                functions_py = re.sub(r"_libraries\['libgnutls.so.26'\] = CDLL\('.*?'\)", "_libraries['libgnutls.so.26'] = CDLL('%s')" % os.path.join(gnutls_dir[1:], 'libgnutls.26.dylib'), functions_py, 1)
        if gnutls_extra_options.index('lgnutls-extra'):
            gnutls_extra_dir = gnutls_extra_options[gnutls_extra_options.index('lgnutls-extra') - 1]
            if gnutls_extra_dir.startswith('L'):
                functions_py = re.sub(r"_libraries\['libgnutls-extra.so.26'\] = CDLL\('.*?'\)", "_libraries['libgnutls-extra.so.26'] = CDLL('%s')" % os.path.join(gnutls_extra_dir[1:], 'libgnutls-extra.26.dylib'), functions_py, 1)
        open('gnutls/library/functions.py', 'w').write(functions_py)
    return include_dirs, library_dirs, libraries

include_dirs, library_dirs, libraries = get_options()

setup(name         = "python-gnutls",
      version      = __version__,
      author       = "Dan Pascu",
      author_email = "dan@ag-projects.com",
      url          = "http://ag-projects.com/",
      download_url = "http://cheeseshop.python.org/pypi/python-gnutls/%s" % __version__,
      description  = title,
      long_description = intro,
      license      = "LGPL",
      platforms    = ["Platform Independent"],
      classifiers  = [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules"
      ],
      packages     = ['gnutls', 'gnutls.interfaces', 'gnutls.interfaces.twisted', 'gnutls.library'],
      ext_modules  = [Extension(name='gnutls.library._gnutls_init',
                          sources=['gnutls/library/_gnutls_init.c'],
                          include_dirs=include_dirs,
                          library_dirs=library_dirs,
                          libraries=libraries)])

