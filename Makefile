
export PYTHONPATH = $(PWD)

HEADER_FILES = /usr/include/gnutls/gnutls.h /usr/include/gnutls/x509.h /usr/include/gnutls/openpgp.h /usr/include/gnutls/extra.h

LIBRARIES = -lgnutls -lgnutls-extra

all: gnutls-library

gnutls-library: gnutls.xml
	mv gnutls/library/__init__.py gnutls/library/__init__.py.tmp
	touch gnutls/library/__init__.py
	xml2py.py gnutls.xml -o gnutls/library/constants.py -v -kde -r ".*[Tt][Ll][Ss].*"
	xml2py.py gnutls.xml -o gnutls/library/types.py -v -kst -r ".*[Tt][Ll][Ss].*" -m gnutls.library.constants
	xml2py.py gnutls.xml -o gnutls/library/functions.py -v -kf -r ".*[Tt][Ll][Ss].*" $(LIBRARIES) -m gnutls.library.types -m gnutls.library.constants
	mv gnutls/library/__init__.py.tmp gnutls/library/__init__.py
	@echo "Fixing wrong argument types"
	@CALLBACKS=`grep FUNCTYPE gnutls/library/types.py | cut -f 1 -d' '`; \
	cp gnutls/library/functions.py gnutls/library/functions.py.bak; \
	for cb in $$CALLBACKS; do \
	    sed -i -r "s/POINTER\($$cb\)/$$cb/g" gnutls/library/functions.py; \
	done

gnutls.xml: $(HEADER_FILES)
	h2xml.py $(HEADER_FILES) -o gnutls.xml -q -c

clean::
	rm -rf *~ gnutls.xml gnutls/__init__.pyc
	(cd gnutls/library; rm -rf *.pyc constants.py types.py functions.py functions.py.bak)

.PHONY: gnutls-library clean
