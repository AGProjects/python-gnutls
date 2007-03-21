
all: gnutls-client

gnutls-client: gnutls-client.c
	gcc -Wall -O2 -g `get-wutil-flags --cflags` -o gnutls-client gnutls-client.c `get-wutil-flags --ldflags --libs` -lgnutls

clean:
	-rm -rf gnutls-client *.o *~ *.pyc *.pyo
