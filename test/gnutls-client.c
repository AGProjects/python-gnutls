/*
 *  Asynchronous gnutls test client, with X.509 authentication.
 *  Uses the WUtil library for connecting on the TCP level.
 *
 *  Copyright (c) 1999-2007 Dan Pascu
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <gnutls/gnutls.h>

#include <WINGs/WINGs.h>


#define TRIES 100

#define KEYFILE "certs/valid.key"
#define CERTFILE "certs/valid.crt"
#define CAFILE "certs/ca.pem"



static int active = TRIES;
static int succesful = 0;
static int failed = 0;

static Bool verify_peer = False;

static int verbose = 0;

static struct timeval start={0, 0}, end={0, 0};

typedef struct TLSSession {
   gnutls_session_t session;     /* the TLS session */
   Bool handshakeDone;           /* the TLS handshake was completed */
   Bool doingBye;                /* processing the TLS bye handshake */
} TLSSession;

static TLSSession tlsSession[TRIES];
static ConnectionDelegate socketDelegate[TRIES];

static void didReceiveInput(ConnectionDelegate *self, WMConnection *cPtr);

static void connectionDidDie(ConnectionDelegate *self, WMConnection *cPtr);

static void didInitialize(ConnectionDelegate *self, WMConnection *cPtr);


void
my_exit(void)
{
    double seconds;

    gettimeofday(&end, NULL);
    seconds = (end.tv_sec + (double)end.tv_usec/1000000.0
               - start.tv_sec - (double)start.tv_usec/1000000.0);
    printf("%.2f seconds; %.2f requests/sec; GNUTLS C async client\n",
           seconds, TRIES/seconds);

    if (failed) {
        printf("%d out of %d connection have failed\n", failed, TRIES);
    }
    
    exit(0);
}


void
wAbort(Bool foo)
{
    exit(1);
}


static Bool
verifyPeerCertificate(gnutls_session_t session, char **reason)
{
    char buffer[1024], *dummy;
    unsigned int status;
    int res;

    if (!verify_peer)
        return True;

    if (reason==NULL)
        reason = &dummy;

    res = gnutls_certificate_verify_peers2(session, &status);
    if (res < 0) {
        snprintf(buffer, 1024, "Couldn't verify certificate: %d, %s", res,
                 gnutls_strerror(res));
        *reason = buffer;
        return False;
    } else {
        if (status & GNUTLS_CERT_INVALID) {
            *reason = "Certificate is invalid";
            return False;
        } else if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
            *reason = "Signer not found";
            return False;
        } else if (status & GNUTLS_CERT_REVOKED) {
            *reason = "Certificate is revoked";
            return False;
        }
    }

    return True;
}


static void
connectionFailed(WMConnection *cPtr, Bool need_close)
{
    if (need_close)
        WMCloseConnection(cPtr);
    active--;
    failed++;
    if (active == 0) {
        my_exit();
    }
}


static void
connectionDone(WMConnection *cPtr)
{
    WMCloseConnection(cPtr);
    active--;
    succesful++;
    if (active == 0) {
        my_exit();
    }
}


static void
didReceiveInput(ConnectionDelegate *self, WMConnection *cPtr)
{
    char buffer[65536], *reason;
    int res;
    TLSSession *tls = self->data;

    if (!tls->handshakeDone) {
        res = gnutls_handshake(tls->session);
        if (res == 0) {
            tls->handshakeDone = True;
            if (!verifyPeerCertificate(tls->session, &reason)) {
                if (verbose)
                    printf("Peer verification failed: %s\n", reason);
                connectionFailed(cPtr, True);
            } else {
                gnutls_record_send(tls->session, "GET /\r\n", 7);
            }
        } else if (res != GNUTLS_E_AGAIN) {
            connectionFailed(cPtr, True);
        }
        return;
    } else if (tls->doingBye) {
        res = gnutls_bye(tls->session, GNUTLS_SHUT_RDWR);
        if (res == GNUTLS_E_AGAIN)
            return;
        connectionDone(cPtr);
        return;
    }

    res = gnutls_record_recv(tls->session, (void*)buffer, 65535);
    if (verbose >= 2)
        printf("received: %d: %s\n", res, buffer);

    res = gnutls_bye(tls->session, GNUTLS_SHUT_RDWR);
    if (res == GNUTLS_E_AGAIN) {
        tls->doingBye = True;
        return;
    }

    connectionDone(cPtr);
}


static void
connectionDidDie(ConnectionDelegate *self, WMConnection *cPtr)
{
    WMCloseConnection(cPtr);
    if (verbose)
        fprintf(stderr, "Connection closed by peer.\n");
    exit(0);
}


static void
didInitialize(ConnectionDelegate *self, WMConnection *cPtr)
{
    int state = WMGetConnectionState(cPtr);
    TLSSession *tls = self->data;
    int res;

    if (state == WCConnected) {
        tls->handshakeDone = False;
        res = gnutls_handshake(tls->session);
        return;
    } else {
        if (verbose)
            wsyserrorwithcode(WCErrorCode, "Unable to connect");
        connectionFailed(cPtr, False);
    }
}


void
print_help(char *ProgName)
{
    printf("Usage: %s [options] [host]\n", ProgName);
#define P(m) puts(m)
    P("");
    P(" -p, --port <port>    port to connect to (10000)");
    P(" -v, --verify         verify peer certificates");
    P(" -n, --no-certs       do not send any certificates");
    P(" -V  --verbose        be verbose (twice for extra verbosity)");
    P(" -h  --help           show this help message and exit");
#undef P
}


int
main(int argc, char **argv)
{
    char *ProgName, *host, *port;
    int i, sock, send_certs;
    gnutls_certificate_credentials_t x509_cred;
    WMConnection *sPtr[TRIES];
    TLSSession *tls;

    wsetabort(wAbort);

    WMInitializeApplication("connect", &argc, argv);

    ProgName = strrchr(argv[0],'/');
    if (!ProgName)
        ProgName = argv[0];
    else
        ProgName++;

    verbose = 0;

    host = NULL;
    port = "10000";
    verify_peer = False;
    send_certs = True;

    if (argc>1) {
        for (i=1; i<argc; i++) {
            if (strcmp(argv[i], "--help")==0 || strcmp(argv[i], "-h")==0) {
                print_help(ProgName);
                exit(0);
            } else if (strcmp(argv[i], "--port")==0 || strcmp(argv[i], "-p")==0) {
                i++;
                if (i>=argc) {
                    wfatal("too few arguments for %s\n", argv[i-1]);
                    exit(1);
                }
                port = argv[i];
            } else if (strcmp(argv[i], "--verify")==0 || strcmp(argv[i], "-v")==0) {
                verify_peer = True;
            } else if (strcmp(argv[i], "--no-certs")==0 || strcmp(argv[i], "-n")==0) {
                send_certs = False;
            } else if (strcmp(argv[i], "--verbose")==0 || strcmp(argv[i], "-V")==0) {
                verbose++;
            } else {
                if (!host) {
                    host = argv[i];
                } else {
                    printf("%s: invalid argument '%s'\n", argv[0], argv[i]);
                    printf("Try '%s --help' for more information\n", argv[0]);
                    exit(1);
                }
            }
        }
    }

    gnutls_global_init();
    gnutls_certificate_allocate_credentials(&x509_cred);
    gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE,
                                           GNUTLS_X509_FMT_PEM);
    if (send_certs) {
        gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, KEYFILE,
                                             GNUTLS_X509_FMT_PEM);
    }


    //printf("Attempting connection to %s:%s\n", host?host:"localhost", port);

    gettimeofday(&start, NULL);

    for (i=0; i<TRIES; i++) {
       sPtr[i] = WMCreateConnectionToAddressAndNotify(host, port, NULL);
       if (!sPtr[i]) {
          wfatal("could not create connection. exiting");
          exit(1);
       }

       tls = &tlsSession[i];

       gnutls_init(&(tls->session), GNUTLS_CLIENT);
       gnutls_set_default_priority(tls->session);

       gnutls_credentials_set(tls->session, GNUTLS_CRD_CERTIFICATE, x509_cred);

       sock = WMGetConnectionSocket(sPtr[i]);
       gnutls_transport_set_ptr(tls->session, (gnutls_transport_ptr_t)sock);

       tls->handshakeDone = False;
       tls->doingBye = False;

       socketDelegate[i].didDie = connectionDidDie;
       socketDelegate[i].didInitialize = didInitialize;
       socketDelegate[i].didReceiveInput = didReceiveInput;
       socketDelegate[i].data = tls;

       WMSetConnectionDelegate(sPtr[i], &socketDelegate[i]);
    }

    active = TRIES;

    while (1) {
        WHandleEvents();
    }

    return 0;

}


