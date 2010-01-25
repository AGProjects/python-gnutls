/*
 * Copyright (C) 2010 AG Projects. See LICENSE for details.
 * Author: Dan Pascu <dan@ag-projects.com>
 *
 * GNUTLS library initialization helpers.
 *
 */

#include <Python.h>

#include <pthread.h>
#include <errno.h>


#define GCRY_THREAD_OPTION_PTHREAD  3
#define GCRY_THREAD_OPTION_VERSION  0

typedef int mutex_callback(void** lock);

typedef struct gcry_thread_cbs {
    unsigned int option;
    void *init;
    mutex_callback *mutex_init;
    mutex_callback *mutex_destroy;
    mutex_callback *mutex_lock;
    mutex_callback *mutex_unlock;
    void *read;
    void *write;
    void *select;
    void *waitpid;
    void *accept;
    void *connect;
    void *sendmsg;
    void *recvmsg;
} gcry_thread_cbs;


static int
gcrypt_mutex_init(void** priv)
{
    pthread_mutex_t *lock = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
    int err = 0;

    if (!lock)
        err = ENOMEM;
    if (!err) {
        err = pthread_mutex_init(lock, NULL);
        if (err) {
            free(lock);
        } else {
            *priv = lock;
        }
    }
    return err;
}


static int
gcrypt_mutex_destroy(void** lock)
{
    int err = pthread_mutex_destroy((pthread_mutex_t*)*lock);
    free(*lock);
    return err;
}


static int
gcrypt_mutex_lock(void** lock)
{
    return pthread_mutex_lock((pthread_mutex_t*)*lock);
}


static int
gcrypt_mutex_unlock(void** lock)
{
    return pthread_mutex_unlock((pthread_mutex_t*)*lock);
}


struct gcry_thread_cbs gcrypt_thread_callbacks = {
    (GCRY_THREAD_OPTION_PTHREAD | (GCRY_THREAD_OPTION_VERSION << 8)),
    NULL, gcrypt_mutex_init, gcrypt_mutex_destroy,
    gcrypt_mutex_lock, gcrypt_mutex_unlock,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};


// List of functions defined in the module
static PyMethodDef methods[] = {
    {NULL, NULL}   // sentinel
};


PyDoc_STRVAR(module_doc,
"This module helps with the GNUTLS library initializations. It contains no\n"
"python code, but it contains the threading callbacks structure that is\n"
"required by the libgcrypt library in order to enable thread safety.");


// Initialization function for the module (must be called init<modulename>)
PyMODINIT_FUNC
init_init(void)
{
    PyObject *module;

    module = Py_InitModule3("_init", methods, module_doc);
    if (module == NULL)
        return;

    PyModule_AddObject(module, "gcrypt_thread_callbacks_ptr", PyLong_FromVoidPtr((void*)&gcrypt_thread_callbacks));

}

