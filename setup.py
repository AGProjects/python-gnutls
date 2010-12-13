#!/usr/bin/env python

from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext
from gnutls import __version__
import os
import re
import sys


class BuildExtension(build_ext):
    def finalize_options(self):
        build_ext.finalize_options(self)
        for extension in self.extensions:
            extension.compiler = self.compiler


class GNUTLSInit(object, Extension):
    def __init__(self):
        Extension.__init__(self, name='gnutls.library._init', sources=['gnutls/library/_init.c'])
        self.compiler = None

    def _get_include_dirs(self):
        if sys.platform == 'win32':
            if self.compiler == 'mingw32':
                return [r'C:\MinGW\include']
            else:
                return [r'C:\Developer\include']
        else:
            return []

    def _get_library_dirs(self):
        if sys.platform == 'win32':
            if self.compiler == 'mingw32':
                return [r'C:\MinGW\lib']
            else:
                return [r'C:\Developer\lib']
        else:
            return []

    def _get_libraries(self):
        if sys.platform=='win32' and self.compiler in ('msvc', None):
            return ['pthreadVC2']
        else:
            return ['pthread']

    def _set_include_dirs(self, value):
        pass

    def _set_library_dirs(self, value):
        pass

    def _set_libraries(self, value):
        pass

    include_dirs = property(_get_include_dirs, _set_include_dirs)
    library_dirs = property(_get_library_dirs, _set_library_dirs)
    libraries = property(_get_libraries, _set_libraries)

    del _get_include_dirs, _set_include_dirs
    del _get_library_dirs, _set_library_dirs
    del _get_libraries, _set_libraries


def find_packages(toplevel):
    return [directory.replace(os.path.sep, '.') for directory, subdirs, files in os.walk(toplevel) if '__init__.py' in files]

# Get the title and description from README
readme = open('README').read()
title, intro = re.findall(r'^\s*([^\n]+)\s+(.*)$', readme, re.DOTALL)[0]

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
      packages     = find_packages('gnutls'),
      ext_modules  = [GNUTLSInit()],
      cmdclass     = {'build_ext': BuildExtension})

