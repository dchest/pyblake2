pyblake2 — BLAKE2 hash function for Python
==========================================

pyblake2 is an extension module for Python implementing BLAKE2 hash function.

BLAKE2_ is a cryptographic hash function, which offers highest security while
being as fast as MD5 or SHA-1, and comes in two flavors:

* **BLAKE2b**, optimized for 64-bit platforms and produces digests of any size
  between 1 and 64 bytes,

* **BLAKE2s**, optimized for 8- to 32-bit platforms and produces digests of any
  size between 1 and 32 bytes.

BLAKE2 supports **keyed mode** (a faster and simpler replacement for HMAC_),
**salted hashing**, **personalization**, and **tree hashing**.

Hash objects from this module follow the API of standard library's
:mod:`hashlib` objects.

.. _BLAKE2: https://blake2.net
.. _HMAC: http://en.wikipedia.org/wiki/Hash-based_message_authentication_code

Contents:

.. toctree::
   :maxdepth: 2

   module
   examples
   installation
   credits
