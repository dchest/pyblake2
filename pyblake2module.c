/*
 * Written in 2013 by Dmitry Chestnykh <dmitry@codingrobots.com>
 *
 * To the extent possible under law, the author have dedicated all
 * copyright and related and neighboring rights to this software to
 * the public domain worldwide. This software is distributed without
 * any warranty. http://creativecommons.org/publicdomain/zero/1.0/
 */

#include <Python.h>

#include "impl/blake2.h"
#include "impl/blake2-impl.h" /* for secure_zero_memory() and store48() */

PyDoc_STRVAR(pyblake2__doc__,
"pyblake2 is an extension module implementing BLAKE2 hash function\n"
"with hashlib-compatible interface.\n"
"\n"
"Examples:\n"
"\n"
"    >>> from pyblake2 import blake2s\n"
"    >>> blake2s(b'cats').hexdigest()\n"
"    'c473a8d190c3867bdaf6529e8d8531925e824cff07f17d489233fde665979f0c'\n"
"\n"
"    >>> from pyblake2 import blake2b\n"
"    >>> h = blake2b(digest_size = 20)\n"
"    >>> h.update(b'Take that, Keccak')\n"
"    >>> h.digest()\n"
"    '\\x98\\xb37\\xfa\\xf5\\xbc\\tY\\xca\\x12\\x19\\x12\\xbd\\xfa"
"\\xd8\\x13z\\xf9\\xffl'\n"
);


/*
 * Python 2-3 compatibility macros.
 */
#if PY_MAJOR_VERSION >= 3
# define COMPAT_PYINT_AS_LONG                    PyLong_AsLong
# define COMPAT_PYINT_FROM_LONG                  PyLong_FromLong
# define COMPAT_PYSTRING_FROM_STRING             PyUnicode_FromString
# define COMPAT_PYSTRING_FROM_STRING_AND_SIZE    PyUnicode_FromStringAndSize
# define COMPAT_PYBYTES_FROM_STRING_AND_SIZE     PyBytes_FromStringAndSize
# define BYTES_FMT                              "y"
#else
# define COMPAT_PYINT_AS_LONG                    PyInt_AsLong
# define COMPAT_PYINT_FROM_LONG                  PyInt_FromLong
# define COMPAT_PYSTRING_FROM_STRING             PyString_FromString
# define COMPAT_PYSTRING_FROM_STRING_AND_SIZE    PyString_FromStringAndSize
# define COMPAT_PYBYTES_FROM_STRING_AND_SIZE     PyString_FromStringAndSize
# define BYTES_FMT                              "s"
#endif

/*
 * Minimum size of buffer when updating hash
 * object for GIL to be released.
 */
#define GIL_MINSIZE 2048

#ifdef WITH_THREAD
# include "pythread.h"

# define OBJECT_LOCK_FIELD PyThread_type_lock lock;

# define ACQUIRE_LOCK(obj)                              \
    if ((obj)->lock) {                                  \
        if (!PyThread_acquire_lock((obj)->lock, 0)) {   \
            Py_BEGIN_ALLOW_THREADS                      \
            PyThread_acquire_lock((obj)->lock, 1);      \
            Py_END_ALLOW_THREADS                        \
        }                                               \
    }

# define RELEASE_LOCK(obj)                      \
    if ((obj)->lock) {                          \
        PyThread_release_lock((obj)->lock);     \
    }

# define INIT_LOCK(obj) do {    \
    (obj)->lock = NULL;         \
} while (0)

# define FREE_LOCK(obj)                     \
    if ((obj)->lock) {                      \
        PyThread_free_lock((obj)->lock);    \
        (obj)->lock = NULL;                 \
    }

#else
# define OBJECT_LOCK_FIELD
# define ACQUIRE_LOCK(obj)
# define RELEASE_LOCK(obj)
# define INIT_LOCK(obj)
# define FREE_LOCK(obj)
#endif /* !WITH_THREAD */

static inline int
getbuffer(PyObject *obj, Py_buffer *bp) {
    if (PyUnicode_Check(obj)) {
        PyErr_SetString(PyExc_TypeError,
                        "Unicode-objects must be encoded before hashing");
        return 0;
    }
    if (!PyObject_CheckBuffer(obj)) {
        PyErr_SetString(PyExc_TypeError,
                        "object supporting the buffer API required");
        return 0;
    }

    if (PyObject_GetBuffer(obj, bp, PyBUF_SIMPLE) == -1)
        return 0;

    if (bp->ndim > 1) {
        PyErr_SetString(PyExc_BufferError, "Buffer must be single dimension");
        PyBuffer_Release(bp);
        return 0;
    }
    return 1;
}

static void
tohex(char *dst, uint8_t *src, size_t srclen)
{
#if PY_VERSION_HEX >= 0x03030000
# define hexdigits Py_hexdigits
#else
    static char hexdigits[] = "0123456789abcdef";
#endif
    size_t i;

    for (i = 0; i < srclen; i++) {
        dst[i*2 + 0] = hexdigits[(src[i] >> 4) & 0x0f];
        dst[i*2 + 1] = hexdigits[src[i] & 0x0f];
    }
}

/*
 * Helpers for setting node offset.
 */

static inline int
blake2b_set_node_offset(blake2b_param *param, uint64_t offset)
{
    param->node_offset = offset;
    return 1;
}

static inline int
blake2s_set_node_offset(blake2s_param *param, uint64_t offset)
{
    if (offset > 0xFFFFFFFFFFFFULL) /* maximum 2**48 - 1 */
        return 0;

    store48(param->node_offset, offset);
    return 1;
}

/*
 * Some aliases needed for parallel versions.
 * TODO: actually implement parallel versions.
 */
#define blake2bp_param  blake2b_param
#define blake2sp_param  blake2s_param

#define blake2bp_set_node_offset    blake2b_set_node_offset
#define blake2sp_set_node_offset    blake2s_set_node_offset

/*
 * Unleash the macros!
 */

#define DECL_BLAKE2_STRUCT(name)        \
    static PyTypeObject name##Type;     \
                                        \
    typedef struct {                    \
        PyObject_HEAD                   \
        name##_param    param;          \
        name##_state    state;          \
        OBJECT_LOCK_FIELD               \
    } name##Object;


#define DECL_NEW_BLAKE2_OBJECT(name)                                    \
    static name##Object *                                               \
    new_##name##Object(void)                                            \
    {                                                                   \
        name##Object *obj;                                              \
        obj = (name##Object *)PyObject_New(name##Object, &name##Type);  \
        if (obj != NULL) INIT_LOCK(obj);                                \
        return obj;                                                     \
    }


static char *kwlist[] = {
    "data", "digest_size", "key", "salt", "person",
    "fanout", "depth", "leaf_size", "node_offset",
    "node_depth", "inner_size", "last_node", NULL
};

#define DECL_INIT_BLAKE2_OBJECT(name, bigname)                                \
    static int                                                                \
    init_##name##Object(name##Object *self, PyObject *args, PyObject *kw)     \
    {                                                                         \
        Py_buffer buf, key, salt, person;                                     \
        PyObject *data = NULL, *last_node_obj = NULL, *fanout_obj = NULL,     \
                 *depth_obj = NULL;                                           \
        unsigned int leaf_size = 0;                                           \
        unsigned PY_LONG_LONG node_offset = 0;                                \
        int node_depth = 0, inner_size = 0, digest_size = bigname##_OUTBYTES; \
        long fanout = 1, depth = 1;                                           \
                                                                              \
        /* Initialize buffers. */                                             \
        key.buf = salt.buf = person.buf = NULL;                               \
                                                                              \
        /* Parse arguments. */                                                \
        if (!PyArg_ParseTupleAndKeywords(args, kw,                            \
                    "|"          /* following arguments are optional */       \
                    "O"          /* `data` as PyObject */                     \
                    "i"          /* `digest_size` as int */                   \
                    BYTES_FMT"*" /* `key` as Py_buffer */                     \
                    BYTES_FMT"*" /* `salt` as Py_buffer */                    \
                    BYTES_FMT"*" /* `person` as Py_buffer */                  \
                    "O"          /* `fanout` as PyObject */                   \
                    "O"          /* `depth` as PyObject */                    \
                    "I"          /* `leaf_size` as unsigned int */            \
                    "K"          /* `node_offset` as unsigned PY_LONG_LONG*/  \
                    "i"          /* `node_depth` as int */                    \
                    "i"          /* `inner_size` as int */                    \
                    "O"          /* `last_node` as PyObject */                \
                    ":"#name"",  /* function name for errors */               \
                    kwlist, &data, &digest_size, &key, &salt, &person,        \
                    &fanout_obj, &depth_obj, &leaf_size, &node_offset,        \
                    &node_depth, &inner_size, &last_node_obj))                \
            goto err0;                                                        \
                                                                              \
        /* Zero parameter block. */                                           \
        memset(&self->param, 0, sizeof(self->param));                         \
                                                                              \
        /* Set digest size. */                                                \
        if (digest_size <= 0 || digest_size > bigname##_OUTBYTES) {           \
            PyErr_Format(PyExc_ValueError,                                    \
                    "digest_size must be between 1 and %d bytes",             \
                    bigname##_OUTBYTES);                                      \
            goto err0;                                                        \
        }                                                                     \
        self->param.digest_length = digest_size;                              \
                                                                              \
        /* Set salt parameter. */                                             \
        if (salt.buf != NULL) {                                               \
            if (salt.len > bigname##_SALTBYTES) {                             \
                PyErr_Format(PyExc_ValueError,                                \
                    "maximum salt length is %d bytes",                        \
                    bigname##_SALTBYTES);                                     \
                goto err0;                                                    \
            }                                                                 \
            memcpy(self->param.salt, salt.buf, salt.len);                     \
        }                                                                     \
                                                                              \
        /* Set personalization parameter. */                                  \
        if (person.buf != NULL) {                                             \
            if (person.len > bigname##_PERSONALBYTES) {                       \
                PyErr_Format(PyExc_ValueError,                                \
                    "maximum person length is %d bytes",                      \
                    bigname##_PERSONALBYTES);                                 \
                goto err0;                                                    \
            }                                                                 \
            memcpy(self->param.personal, person.buf, person.len);             \
        }                                                                     \
                                                                              \
        /* Set tree parameters. */                                            \
        if (fanout_obj != NULL) {                                             \
            fanout = COMPAT_PYINT_AS_LONG(fanout_obj);                        \
            if (fanout == -1 && PyErr_Occurred())                             \
                goto err0;                                                    \
        }                                                                     \
        if (fanout < 0 || fanout > 255) {                                     \
            PyErr_SetString(PyExc_ValueError,                                 \
                    "fanout must be between 0 and 255");                      \
            goto err0;                                                        \
        }                                                                     \
        self->param.fanout = (uint8_t)fanout;                                 \
                                                                              \
        if (depth_obj != NULL) {                                              \
            depth = COMPAT_PYINT_AS_LONG(depth_obj);                          \
            if (depth == -1 && PyErr_Occurred())                              \
                goto err0;                                                    \
        }                                                                     \
        if (depth <= 0 || depth > 255) {                                      \
            PyErr_SetString(PyExc_ValueError,                                 \
                    "depth must be between 1 and 255");                       \
            goto err0;                                                        \
        }                                                                     \
        self->param.depth = (uint8_t)depth;                                   \
                                                                              \
        self->param.leaf_length = leaf_size;                                  \
                                                                              \
        if (!name##_set_node_offset(&self->param, node_offset)) {             \
            PyErr_SetString(PyExc_ValueError, "node_offset is too large");    \
            goto err0;                                                        \
        }                                                                     \
                                                                              \
        if (node_depth < 0 || node_depth > 255) {                             \
            PyErr_SetString(PyExc_ValueError,                                 \
                    "node_depth must be between 0 and 255");                  \
            goto err0;                                                        \
        }                                                                     \
        self->param.node_depth = node_depth;                                  \
                                                                              \
        if (inner_size < 0 || inner_size > bigname##_OUTBYTES) {              \
            PyErr_Format(PyExc_ValueError,                                    \
                    "inner_size must be between 0 and is %d",                 \
                    bigname##_OUTBYTES);                                      \
            goto err0;                                                        \
        }                                                                     \
        self->param.inner_length = inner_size;                                \
                                                                              \
        /* Set key length. */                                                 \
        if (key.buf != NULL && key.len > 0) {                                 \
            if (key.len > bigname##_KEYBYTES) {                               \
                PyErr_Format(PyExc_ValueError,                                \
                    "maximum key length is %d bytes",                         \
                    bigname##_KEYBYTES);                                      \
                goto err0;                                                    \
            }                                                                 \
            self->param.key_length = key.len;                                 \
        }                                                                     \
                                                                              \
        /* Initialize hash state. */                                          \
        if (name##_init_param(&self->state, &self->param) < 0) {              \
            PyErr_SetString(PyExc_RuntimeError,                               \
                    "error initializing hash state");                         \
            goto err0;                                                        \
        }                                                                     \
                                                                              \
        /* Set last node flag (must come after initialization). */            \
        self->state.last_node = (last_node_obj != NULL &&                     \
                    PyObject_IsTrue(last_node_obj));                          \
                                                                              \
        /* Process key block if any. */                                       \
        if (key.buf != NULL && key.len > 0) {                                 \
            uint8_t block[bigname##_BLOCKBYTES];                              \
            memset(block, 0, sizeof(block));                                  \
            memcpy(block, key.buf, key.len);                                  \
            name##_update(&self->state, block, sizeof(block));                \
            secure_zero_memory(block, sizeof(block));                         \
        }                                                                     \
                                                                              \
        /* Process initial data if any. */                                    \
        if (data != NULL) {                                                   \
            if (!getbuffer(data, &buf))                                       \
                goto err0;                                                    \
                                                                              \
            if (buf.len >= GIL_MINSIZE) {                                     \
                Py_BEGIN_ALLOW_THREADS                                        \
                name##_update(&self->state, buf.buf, buf.len);                \
                Py_END_ALLOW_THREADS                                          \
            } else {                                                          \
                name##_update(&self->state, buf.buf, buf.len);                \
            }                                                                 \
            PyBuffer_Release(&buf);                                           \
        }                                                                     \
                                                                              \
        /* Release buffers. */                                                \
        if (key.buf != NULL)                                                  \
            PyBuffer_Release(&key);                                           \
        if (salt.buf != NULL)                                                 \
            PyBuffer_Release(&salt);                                          \
        if (person.buf != NULL)                                               \
            PyBuffer_Release(&person);                                        \
                                                                              \
        return 1;                                                             \
                                                                              \
    err0:                                                                     \
        /* Error: release buffers. */                                         \
        if (key.buf != NULL)                                                  \
            PyBuffer_Release(&key);                                           \
        if (salt.buf != NULL)                                                 \
            PyBuffer_Release(&salt);                                          \
        if (person.buf != NULL)                                               \
            PyBuffer_Release(&person);                                        \
                                                                              \
        return 0;                                                             \
    }


/*
 * Methods.
 */

#define DECL_PY_BLAKE2_COPY(name)                               \
    PyDoc_STRVAR(py_##name##_copy__doc__,                       \
    "Return a copy of the hash object.");                       \
                                                                \
    static PyObject *                                           \
    py_##name##_copy(name##Object *self, PyObject *unused)      \
    {                                                           \
        name##Object *cpy;                                      \
                                                                \
        if ((cpy = new_##name##Object()) == NULL)               \
            return NULL;                                        \
                                                                \
        ACQUIRE_LOCK(self);                                     \
        cpy->param = self->param;                               \
        cpy->state = self->state;                               \
        RELEASE_LOCK(self);                                     \
        return (PyObject *)cpy;                                 \
    }


/*
 * Macro used inside DECL_PY_BLAKE2_UPDATE:
 */
#ifdef WITH_THREAD
/* With threads:
 * Update hash object with buffer, releasing GIL if length of buffer
 * is greater than or equal to GIL_MINSIZE.
 */
# define INNER_UPDATE(name) do {                                    \
    if (self->lock == NULL && buf.len >= GIL_MINSIZE)               \
        self->lock = PyThread_allocate_lock();                      \
                                                                    \
    if (self->lock != NULL) {                                       \
       Py_BEGIN_ALLOW_THREADS                                       \
       PyThread_acquire_lock(self->lock, 1);                        \
       name##_update(&self->state, buf.buf, buf.len);               \
       PyThread_release_lock(self->lock);                           \
       Py_END_ALLOW_THREADS                                         \
    } else {                                                        \
        name##_update(&self->state, buf.buf, buf.len);              \
    }                                                               \
} while (0)

#else
/* Without threads:
 * just update hash object with buffer.
 */
# define INNER_UPDATE(name) do {                                    \
    name##_update(&self->state, buf.buf, buf.len);                  \
} while (0)

#endif /* !WITH_THREAD */


#define DECL_PY_BLAKE2_UPDATE(name)                                         \
    PyDoc_STRVAR(py_##name##_update__doc__,                                 \
    "Update the hash object with the object, which must be interpretable "  \
    "as buffer of bytes.");                                                 \
                                                                            \
    static PyObject *                                                       \
    py_##name##_update(name##Object *self, PyObject *args)                  \
    {                                                                       \
        PyObject  *obj;                                                     \
        Py_buffer buf;                                                      \
                                                                            \
        if (!PyArg_ParseTuple(args, "O:update", &obj))                      \
            return NULL;                                                    \
                                                                            \
        if (!getbuffer(obj, &buf))                                          \
            return NULL;                                                    \
                                                                            \
        INNER_UPDATE(name);                                                 \
        PyBuffer_Release(&buf);                                             \
                                                                            \
        Py_INCREF(Py_None);                                                 \
        return Py_None;                                                     \
    }


#define DECL_PY_BLAKE2_DIGEST(name, bigname)                                \
    PyDoc_STRVAR(py_##name##_digest__doc__,                                 \
    "Return the digest of the data so far.");                               \
                                                                            \
    static PyObject *                                                       \
    py_##name##_digest(name##Object *self, PyObject *unused)                \
    {                                                                       \
        uint8_t digest[bigname##_OUTBYTES];                                 \
        name##_state state_cpy;                                             \
                                                                            \
        ACQUIRE_LOCK(self);                                                 \
        state_cpy = self->state;                                            \
        name##_final(&state_cpy, digest, self->param.digest_length);        \
        RELEASE_LOCK(self);                                                 \
        return COMPAT_PYBYTES_FROM_STRING_AND_SIZE((const char *)digest,    \
                self->param.digest_length);                                 \
    }


#define DECL_PY_BLAKE2_HEXDIGEST(name, bigname)                             \
    PyDoc_STRVAR(py_##name##_hexdigest__doc__,                              \
    "Like digest() except the digest is returned as a string of double "    \
    "length, containing only hexadecimal digits.");                         \
                                                                            \
    static PyObject *                                                       \
    py_##name##_hexdigest(name##Object *self, PyObject *unused)             \
    {                                                                       \
        uint8_t digest[bigname##_OUTBYTES];                                 \
        char hexdigest[sizeof(digest) * 2];                                 \
        name##_state state_cpy;                                             \
                                                                            \
        ACQUIRE_LOCK(self);                                                 \
        state_cpy = self->state;                                            \
        name##_final(&state_cpy, digest, self->param.digest_length);        \
        tohex(hexdigest, digest, self->param.digest_length);                \
        RELEASE_LOCK(self);                                                 \
        return COMPAT_PYSTRING_FROM_STRING_AND_SIZE((const char *)hexdigest,\
                self->param.digest_length * 2);                             \
    }


#define DECL_PY_BLAKE2_METHODS(name)                                    \
    static PyMethodDef name##_methods[] = {                             \
        {"copy", (PyCFunction)py_##name##_copy, METH_NOARGS,            \
            py_##name##_copy__doc__},                                   \
        {"digest", (PyCFunction)py_##name##_digest, METH_NOARGS,        \
            py_##name##_digest__doc__},                                 \
        {"hexdigest", (PyCFunction)py_##name##_hexdigest, METH_NOARGS,  \
            py_##name##_hexdigest__doc__},                              \
        {"update", (PyCFunction)py_##name##_update, METH_VARARGS,       \
            py_##name##_update__doc__},                                 \
        {NULL, NULL}                                                    \
    };

/*
 * Getters.
 */

#define DECL_PY_BLAKE2_GET_NAME(name)                       \
    static PyObject *                                       \
    py_##name##_get_name(name##Object *self, void *closure) \
    {                                                       \
        return COMPAT_PYSTRING_FROM_STRING("" #name "");    \
    }


#define DECL_PY_BLAKE2_GET_BLOCK_SIZE(name, bigname)                \
    static PyObject *                                               \
    py_##name##_get_block_size(name##Object *self, void *closure)   \
    {                                                               \
        return COMPAT_PYINT_FROM_LONG(bigname##_BLOCKBYTES);        \
    }


#define DECL_PY_BLAKE2_GET_DIGEST_SIZE(name)                        \
    static PyObject *                                               \
    py_##name##_get_digest_size(name##Object *self, void *closure)  \
    {                                                               \
        return COMPAT_PYINT_FROM_LONG(self->param.digest_length);   \
    }


#define DECL_PY_BLAKE2_GETSETTERS(name)                             \
    static PyGetSetDef name##_getsetters[] = {                      \
        {"name", (getter)py_##name##_get_name,                      \
            NULL, NULL, NULL},                                      \
        {"block_size", (getter)py_##name##_get_block_size,          \
            NULL, NULL, NULL},                                      \
        {"digest_size", (getter)py_##name##_get_digest_size,        \
            NULL, NULL, NULL},                                      \
        {NULL}                                                      \
    };


#define DECL_PY_BLAKE2_DEALLOC(name)                            \
    static void                                                 \
    py_##name##_dealloc(PyObject *self)                         \
    {                                                           \
        name##Object *obj = (name##Object *)self;               \
                                                                \
        /* Try not to leave state in memory. */                 \
        secure_zero_memory(&obj->param, sizeof(obj->param));    \
        secure_zero_memory(&obj->state, sizeof(obj->state));    \
        FREE_LOCK(obj);                                         \
        PyObject_Del(self);                                     \
    }


#define DECL_PY_BLAKE2_TYPE_OBJECT(name)                    \
    static PyTypeObject name##Type = {                      \
        PyVarObject_HEAD_INIT(NULL, 0)                      \
        "pyblake2." #name,        /* tp_name            */  \
        sizeof(name##Object),     /* tp_size            */  \
        0,                        /* tp_itemsize        */  \
        py_##name##_dealloc,      /* tp_dealloc         */  \
        0,                        /* tp_print           */  \
        0,                        /* tp_getattr         */  \
        0,                        /* tp_setattr         */  \
        0,                        /* tp_compare         */  \
        0,                        /* tp_repr            */  \
        0,                        /* tp_as_number       */  \
        0,                        /* tp_as_sequence     */  \
        0,                        /* tp_as_mapping      */  \
        0,                        /* tp_hash            */  \
        0,                        /* tp_call            */  \
        0,                        /* tp_str             */  \
        0,                        /* tp_getattro        */  \
        0,                        /* tp_setattro        */  \
        0,                        /* tp_as_buffer       */  \
        Py_TPFLAGS_DEFAULT,       /* tp_flags           */  \
        0,                        /* tp_doc             */  \
        0,                        /* tp_traverse        */  \
        0,                        /* tp_clear           */  \
        0,                        /* tp_richcompare     */  \
        0,                        /* tp_weaklistoffset  */  \
        0,                        /* tp_iter            */  \
        0,                        /* tp_iternext        */  \
        name##_methods,           /* tp_methods         */  \
        0,                        /* tp_members         */  \
        name##_getsetters,        /* tp_getset          */  \
    };


#define DECL_PY_BLAKE2_NEW(name)                                        \
    static PyObject *                                                   \
    py_##name##_new(PyObject *self, PyObject *args, PyObject *kwdict)   \
    {                                                                   \
        name##Object *obj;                                              \
                                                                        \
        if ((obj = new_##name##Object()) == NULL)                       \
            goto err0;                                                  \
                                                                        \
        if (PyErr_Occurred())                                           \
            goto err1;                                                  \
                                                                        \
        if (!init_##name##Object(obj, args, kwdict))                    \
            goto err1;                                                  \
                                                                        \
        return (PyObject *)obj;                                         \
                                                                        \
    err1:                                                               \
        Py_DECREF(obj);                                                 \
    err0:                                                               \
        return NULL;                                                    \
    }


#define DECL_BLAKE2_WRAPPER(name, bigname)          \
    DECL_BLAKE2_STRUCT(name)                        \
    DECL_NEW_BLAKE2_OBJECT(name)                    \
    DECL_INIT_BLAKE2_OBJECT(name, bigname)          \
    DECL_PY_BLAKE2_COPY(name)                       \
    DECL_PY_BLAKE2_UPDATE(name)                     \
    DECL_PY_BLAKE2_DIGEST(name, bigname)            \
    DECL_PY_BLAKE2_HEXDIGEST(name, bigname)         \
    DECL_PY_BLAKE2_METHODS(name)                    \
    DECL_PY_BLAKE2_GET_NAME(name)                   \
    DECL_PY_BLAKE2_GET_BLOCK_SIZE(name, bigname)    \
    DECL_PY_BLAKE2_GET_DIGEST_SIZE(name)            \
    DECL_PY_BLAKE2_GETSETTERS(name)                 \
    DECL_PY_BLAKE2_DEALLOC(name)                    \
    DECL_PY_BLAKE2_TYPE_OBJECT(name)                \
    DECL_PY_BLAKE2_NEW(name)

/*
 * Declare objects.
 * Note: don't forget to update module init function and constants.
 */

PyDoc_STRVAR(py_blake2b_new__doc__,
"blake2b(data=b'', digest_size=64, key=b'', salt=b'', person=b'', "
"fanout=1, depth=1, leaf_size=0, node_offset=0, node_depth=0, "
"inner_size=0, last_node=False) -> blake2b object\n"
"\n"
"Return a new BLAKE2b hash object.");

DECL_BLAKE2_WRAPPER(blake2b, BLAKE2B)


PyDoc_STRVAR(py_blake2s_new__doc__,
"blake2s(data=b'', digest_size=32, key=b'', salt=b'', person=b'', "
"fanout=1, depth=1, leaf_size=0, node_offset=0, node_depth=0, "
"inner_size=0, last_node=False) -> blake2s object\n"
"\n"
"Return a new BLAKE2s hash object.");

DECL_BLAKE2_WRAPPER(blake2s, BLAKE2S)


/*
 * Module.
 */
static struct PyMethodDef pyblake2_functions[] = {
    {"blake2b", (PyCFunction)py_blake2b_new, METH_VARARGS|METH_KEYWORDS,
        py_blake2b_new__doc__},
    {"blake2s", (PyCFunction)py_blake2s_new, METH_VARARGS|METH_KEYWORDS,
        py_blake2s_new__doc__},
    {NULL, NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef pyblake2_module = {
    PyModuleDef_HEAD_INIT,
    "pyblake2",
    pyblake2__doc__,
    -1,
    pyblake2_functions,
    NULL,
    NULL,
    NULL,
    NULL
};
# define INIT_FUNC_NAME PyInit_pyblake2
# define INIT_ERROR     return NULL
#else
# define INIT_FUNC_NAME initpyblake2
# define INIT_ERROR     return
#endif

PyMODINIT_FUNC
INIT_FUNC_NAME(void)
{
    PyObject *m;

    Py_TYPE(&blake2bType) = &PyType_Type;
    if (PyType_Ready(&blake2bType) < 0)
        INIT_ERROR;

    Py_TYPE(&blake2sType) = &PyType_Type;
    if (PyType_Ready(&blake2sType) < 0)
        INIT_ERROR;

    /* TODO: do runtime self-check */
#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&pyblake2_module);
#else
    m = Py_InitModule3("pyblake2", pyblake2_functions, pyblake2__doc__);
#endif

    /* Add module constants. */

    PyModule_AddIntConstant(m, "BLAKE2B_SALT_SIZE", BLAKE2B_SALTBYTES);
    PyModule_AddIntConstant(m, "BLAKE2B_PERSON_SIZE", BLAKE2B_PERSONALBYTES);
    PyModule_AddIntConstant(m, "BLAKE2B_MAX_KEY_SIZE", BLAKE2B_KEYBYTES);
    PyModule_AddIntConstant(m, "BLAKE2B_MAX_DIGEST_SIZE", BLAKE2B_OUTBYTES);

    PyModule_AddIntConstant(m, "BLAKE2S_SALT_SIZE", BLAKE2S_SALTBYTES);
    PyModule_AddIntConstant(m, "BLAKE2S_PERSON_SIZE", BLAKE2S_PERSONALBYTES);
    PyModule_AddIntConstant(m, "BLAKE2S_MAX_KEY_SIZE", BLAKE2S_KEYBYTES);
    PyModule_AddIntConstant(m, "BLAKE2S_MAX_DIGEST_SIZE", BLAKE2S_OUTBYTES);

#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}

/* vim: set expandtab ts=4 sw=4: */
