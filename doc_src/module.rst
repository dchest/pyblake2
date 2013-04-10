Module
======

.. module:: pyblake2

Creating hash objects
---------------------

New hash objects are created by calling constructor functions:


.. function:: blake2b(data=b'', digest_size=64, key=b'', salt=b'', \
                person=b'', fanout=1, depth=1, leaf_size=0, node_offset=0,  \
                node_depth=0, inner_size=0, last_node=False)

.. function:: blake2s(data=b'', digest_size=32, key=b'', salt=b'', \
                person=b'', fanout=1, depth=1, leaf_size=0, node_offset=0,  \
                node_depth=0, inner_size=0, last_node=False)


These functions return the corresponding hash objects for calculating
BLAKE2b or BLAKE2s. They optionally take these general parameters:

* `data`: initial chunk of data to hash, which must be interpretable as buffer
  of bytes.

* `digest_size`: size of output digest in bytes.

* `key`: key for keyed hashing (up to 64 bytes for BLAKE2b, up to 32 bytes for
  BLAKE2s).

* `salt`: salt for randomized hashing (up to 16 bytes for BLAKE2b, up to 8
  bytes for BLAKE2s).

* `person`: personalization string (up to 16 bytes for BLAKE2b, up to 8 bytes
  for BLAKE2s).

The following table shows limits for general parameters (in bytes):

======= =========== ======== ========= ===========
Hash    digest_size len(key) len(salt) len(person)
======= =========== ======== ========= ===========
BLAKE2b     64         64       16        16
BLAKE2s     32         32       8         8
======= =========== ======== ========= ===========

.. note::

    BLAKE2 specification defines constant lengths for salt and personalization
    parameters, however, for convenience, this implementation accepts byte
    strings of any size up to the specified length. If the length of the
    parameter is less than specified, it is padded with zeros, thus, for
    example, ``b'salt'`` and ``b'salt\x00'`` is the same value. (This is not
    the case for `key`.)

These sizes are available as module `constants`_ described below.

Constructor functions also accept the following tree hashing parameters:

* `fanout`: fanout (0 to 255, 0 if unlimited, 1 in sequential mode).

* `depth`: maximal depth of tree (1 to 255, 255 if unlimited, 1 in
  sequential mode).

* `leaf_size`: maximal byte length of leaf (0 to 2**32-1, 0 if unlimited or in
  sequential mode).

* `node_offset`: node offset (0 to 2**64-1 for BLAKE2b, 0 to 2**48-1 for
  BLAKE2s, 0 for the first, leftmost, leaf, or in sequential mode).

* `node_depth`: node depth (0 to 255, 0 for leaves, or in sequential mode).

* `inner_size`: inner digest size (0 to 64 for BLAKE2b, 0 to 32 for
  BLAKE2s, 0 in sequential mode).

* `last_node`: boolean indicating whether the processed node is the last
  one (`False` for sequential mode).

.. figure:: tree.png
   :alt: Explanation of tree mode parameters.

See section 2.10 in `BLAKE2 specification
<https://blake2.net/blake2_20130129.pdf>`_ for comprehensive review of tree
hashing.


Using hash objects
------------------

Hash objects have the following attributes and methods:


.. data:: hash.digest_size

The size of the resulting digest in bytes. This is the value given to hash
object constructor in `digest_size` argument.


.. data:: hash.block_size

The internal block size of the hash algorithm in bytes.


.. method:: hash.update(arg)

Update the hash object with the object, which must be interpretable as buffer
of bytes

.. note::

    For better multithreading performance, the Python GIL is released for data
    larger than 2047 bytes at hash object creation or on update to allow other
    threads to run.


.. method:: hash.digest()

Return the digest of the data so far.


.. method:: hash.hexdigest()

Like :meth:`digest` except the digest is returned as a string of double
length, containing only hexadecimal digits.


.. method:: hash.copy()

Return a copy of the hash object.


Constants
---------

.. data:: BLAKE2B_SALT_SIZE
.. data:: BLAKE2S_SALT_SIZE

Salt length (maximum length accepted by constructors).


.. data:: BLAKE2B_PERSON_SIZE
.. data:: BLAKE2S_PERSON_SIZE

Personalization string length (maximum length accepted by constructors).


.. data:: BLAKE2B_MAX_KEY_SIZE
.. data:: BLAKE2S_MAX_KEY_SIZE

Maximum key size.


.. data:: BLAKE2B_MAX_DIGEST_SIZE
.. data:: BLAKE2S_MAX_DIGEST_SIZE

Maximum digest size that the hash function can output.


