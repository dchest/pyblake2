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
import os

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

try:
    readme_content = open(os.path.join(os.path.abspath(
        os.path.dirname(__file__)), "README")).read()
except Exception:
    readme_content = __doc__

pyblake2 = Extension('pyblake2',
                     define_macros=[
                         # Which implementation to use for compression function:
                         ('BLAKE2_COMPRESS_REGS', '1'),  # fast portable
                         #('BLAKE2_COMPRESS_SSE2', '1'),  # x86 SSE2 (may be slower than 'regs')
                         #('BLAKE2_COMPRESS_SSSE3', '1'), # x86 SSSE3
                         #('BLAKE2_COMPRESS_AVX', '1'),   # x86 AVX
                         #('BLAKE2_COMPRESS_XOP', '1'),   # x86 XOP
                         ],
                     # Extra flags.
                     #extra_compile_args = ['-msse4.1'],
                     sources=[
                         'pyblake2module.c',
                         'impl/blake2b.c',
                         'impl/blake2s.c',
                         ],
                     depends=['*.h'])


tests_require = [
    'six']

setup(name='pyblake2',
      version='0.9.1',
      description='BLAKE2 hash function extension module',
      long_description=readme_content,
      author='Dmitry Chestnykh',
      author_email='dmitry@codingrobots.com',
      license='http://creativecommons.org/publicdomain/zero/1.0/',
      url='https://github.com/dchest/pyblake2',
      ext_modules=[pyblake2],
      tests_require=tests_require,
      classifiers=[
            'Development Status :: 4 - Beta',
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
            'Topic :: Security :: Cryptography'
          ],
      test_suite='test.test.testsuite',
      )
