/*
 * Copyright (C) 2007 AG Projects. See LICENSE for details.
 * Author: Dan Pascu <dan@ag-projects.com>
 *
 * GNUTLS library initializations.
 *
 */

#include <Python.h>

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gcrypt.h>
#include <errno.h>
#include <pthread.h>

// Use POSIX threads for libgcrypt locking
GCRY_THREAD_OPTION_PTHREAD_IMPL;

// List of functions defined in the module
static PyMethodDef gnutls_methods[] = {
    {NULL, NULL}   // sentinel
};

PyDoc_STRVAR(module_doc,
"This module does behind the scenes GNUTLS initializations, like for example\n"
"enabling thread safety in the gcrypt library and calling the GNUTLS global\n"
"initialization functions.");

// Initialization function for the module (must be called init_gnutls_init)
PyMODINIT_FUNC
init_gnutls_init(void)
{
    PyObject *m;

    m = Py_InitModule3("_gnutls_init", gnutls_methods, module_doc);
    if (m == NULL)
        return;

    // Enable thread safety for the posix threads library.
    // This must be done before calling gnutls_global_init().
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

    gnutls_global_init();
    gnutls_global_init_extra();
}

