from distutils.core import setup, Extension

pyblake2 = Extension('pyblake2',
                   sources = [
                       'pyblake2module.c',
                       'impl/blake2b-regs.c',
                       'impl/blake2s-regs.c',
                   ])

setup(name='pyblake2',
      version='0.1',
      description='BLAKE2 module for Python',
      author='Dmitry Chestnykh',
      author_email='dmitry@codingrobots.com',
      license='http://creativecommons.org/publicdomain/zero/1.0/',
      url='https://github.com/dchest/pyblake2',
      ext_modules=[pyblake2])

