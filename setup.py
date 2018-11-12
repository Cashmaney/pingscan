import sys
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

SRC_DIR = "pingscan"
PACKAGES = [SRC_DIR]

with open("README.rst", "r") as fh:
    long_description = fh.read()

extensions = []

if '--use-cython' in sys.argv:
    USE_CYTHON = True
    sys.argv.remove('--use-cython')
else:
    USE_CYTHON = False

ext = '.pyx' if USE_CYTHON else '.c'
extensions = [Extension(SRC_DIR + ".c_icmp",
                        [SRC_DIR + "/c_icmp" + ext],
                        language='c')]
cmd = {'build_ext': build_ext}

if USE_CYTHON:
    from Cython.Build import cythonize
    from Cython.Distutils import build_ext as cy_build_ext
    extensions = cythonize(extensions)
    cmd = {'build_ext': cy_build_ext}

setup(
    cmdclass            =cmd,
    ext_modules         =extensions,
    name                ='pingscan',
    version             ='1.0.0',
    description         ='A multiprocessing async ping scanner',
    long_description    =long_description,
    long_description_content_type="text/markdown",
    url                 ="https://github.com/Cashmaney/pingscan",
    author              ='Itzik Grossman',
    author_email        ='itzygro@gmail.com',
    python_requires     ='>=3.6, <4',
    license             ='MIT License',
    packages            =PACKAGES,
    include_package_data=True,
    package_data={SRC_DIR: ['*.c', '*.pyx']},
    classifiers         =[
        'Programming Language :: Python',
        'Programming Language :: Cython',
        'Natural Language :: English',
        'Environment :: Plugins',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Topic :: System :: Monitoring',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
