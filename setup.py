from distutils.core import setup, Extension

pyblake2 = Extension('pyblake2',
                   define_macros = [
                    # Which implementation to use for compression function:
                    ('BLAKE2_COMPRESS_REGS', '1'),  # fast portable
                    #('BLAKE2_COMPRESS_SSE2', '1'),  # x86 SSE2 (may be slower than 'regs')
                    #('BLAKE2_COMPRESS_SSSE3', '1'), # x86 SSSE3
                    #('BLAKE2_COMPRESS_AVX', '1'),   # x86 AVX
                    #('BLAKE2_COMPRESS_XOP', '1'),   # x86 XOP
                   ],
                   # Extra flags required for AVX:
                   #extra_compile_args = ['-msse4.1'],
                   sources = [
                       'pyblake2module.c',
                       'impl/blake2b.c',
                       'impl/blake2s.c',
                   ],
                   depends = ['*.h'])


setup(name='pyblake2',
      version='0.1',
      description='BLAKE2 module for Python',
      author='Dmitry Chestnykh',
      author_email='dmitry@codingrobots.com',
      license='http://creativecommons.org/publicdomain/zero/1.0/',
      url='https://github.com/dchest/pyblake2',
      ext_modules=[pyblake2])

