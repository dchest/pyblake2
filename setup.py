"""
pyblake2 is an extension module for Python implementing BLAKE2 hash function.

BLAKE2 is a cryptographic hash function, which offers highest security while
being as fast as MD5 or SHA-1, and comes in two flavors:

* BLAKE2b, optimized for 64-bit platforms and produces digests of any size
  between 1 and 64 bytes,

* BLAKE2s, optimized for 8- to 32-bit platforms and produces digests of any
  size between 1 and 32 bytes.

BLAKE2 supports keyed mode (a faster and simpler replacement for HMAC),
salted hashing, personalization, and tree hashing.

Hash objects from this module follow the API of standard library's
`hashlib` objects.
"""

from setuptools import setup, Extension

# Version of optimized implementation to use.

opt_version = 'BLAKE2_COMPRESS_AUTO'

# By default, pyblake2 automatically selects the optimization based
# on CPU indicated by CFLAGS. If you'd like to override the default
# choice, you can uncomment one of the following options. Note that
# you might need to add additional machine flags via extra_compile_args
# below.

#opt_version = 'BLAKE2_COMPRESS_REGS'  # fast portable
#opt_version = 'BLAKE2_COMPRESS_SSE2'  # x86 SSE2 (slow!)
#opt_version = 'BLAKE2_COMPRESS_SSSE3' # x86 SSSE3
#opt_version = 'BLAKE2_COMPRESS_AVX'   # x86 AVX
#opt_version = 'BLAKE2_COMPRESS_XOP'   # x86 XOP

pyblake2 = Extension('pyblake2',
                     define_macros=[
                         (opt_version, '1')
                         ],
                     #extra_compile_args = ['-msse4.1'],
                     sources=[
                         'pyblake2module.c',
                         'blake2b_impl.c',
                         'blake2s_impl.c',
                         ],
                     depends=['*.h'])


setup(name='pyblake2',
      version='1.1.2',
      description='BLAKE2 hash function extension module',
      long_description=__doc__,
      author='Dmitry Chestnykh',
      author_email='dmitry@codingrobots.com',
      license='http://creativecommons.org/publicdomain/zero/1.0/',
      url='https://github.com/dchest/pyblake2',
      ext_modules=[pyblake2],
      classifiers=[
          'Intended Audience :: Developers',
          'Intended Audience :: Information Technology',
          'Intended Audience :: Science/Research',
          'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.0',
          'Programming Language :: Python :: 3.1',
          'Programming Language :: Python :: 3.2',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Topic :: Security :: Cryptography'
          ]
     )

