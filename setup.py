from distutils.core import setup, Extension

LONG_DESC = """\
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

pyblake2 = Extension('pyblake2',
                   define_macros = [
                    # Which implementation to use for compression function:
                    ('BLAKE2_COMPRESS_REGS', '1'),  # fast portable
                    #('BLAKE2_COMPRESS_SSE2', '1'),  # x86 SSE2 (may be slower than 'regs')
                    #('BLAKE2_COMPRESS_SSSE3', '1'), # x86 SSSE3
                    #('BLAKE2_COMPRESS_AVX', '1'),   # x86 AVX
                    #('BLAKE2_COMPRESS_XOP', '1'),   # x86 XOP
                   ],
                   # Extra flags.
                   #extra_compile_args = ['-msse4.1'],
                   sources = [
                       'pyblake2module.c',
                       'impl/blake2b.c',
                       'impl/blake2s.c',
                   ],
                   depends = ['*.h'])


setup(name='pyblake2',
      version='0.9.0',
      description='BLAKE2 hash function extension module',
      long_description=LONG_DESC,
      author='Dmitry Chestnykh',
      author_email='dmitry@codingrobots.com',
      license='http://creativecommons.org/publicdomain/zero/1.0/',
      url='https://github.com/dchest/pyblake2',
      ext_modules=[pyblake2],
      classifiers=[
            'Classifier: Development Status :: 4 - Beta',
            'Classifier: Intended Audience :: Developers',
            'Classifier: Intended Audience :: Information Technology',
            'Classifier: Intended Audience :: Science/Research',
            'Classifier: License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',
            'Classifier: Operating System :: OS Independent',
            'Classifier: Programming Language :: Python :: 2',
            'Classifier: Programming Language :: Python :: 2.6',
            'Classifier: Programming Language :: Python :: 2.7',
            'Classifier: Programming Language :: Python :: 3',
            'Classifier: Programming Language :: Python :: 3.0',
            'Classifier: Programming Language :: Python :: 3.1',
            'Classifier: Programming Language :: Python :: 3.2',
            'Classifier: Programming Language :: Python :: 3.3',
            'Classifier: Topic :: Security :: Cryptography'
          ]
      )

