#!/usr/bin/python

from distutils.core import setup, Extension
from gnutls import __version__

# Get the title and description from README
import re
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
      packages     = ['gnutls', 'gnutls.interfaces', 'gnutls.interfaces.twisted', 'gnutls.library'],
      ext_modules  = [Extension(name='gnutls.library._gnutls_init',
                          sources=['gnutls/library/_gnutls_init.c'],
                          include_dirs=[],
                          library_dirs=[],
                          libraries=['gcrypt', 'gnutls', 'gnutls-extra'])])

