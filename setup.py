from distutils.core import setup
from Cython.Build import cythonize
from setuptools import setup, Extension
from Cython.Distutils import build_ext

SRC_DIR = "cy_src"
PACKAGES = [SRC_DIR]

REQUIRES = ['cython']

ext_1 = Extension(SRC_DIR + ".c_icmp",
                  [SRC_DIR + "/c_icmp.pyx"])

EXTENSIONS = [ext_1]

setup(
    install_requires    =REQUIRES,
    cmdclass            ={"build_ext": build_ext},
    ext_modules         =EXTENSIONS,
    name                ='Pingscan',
    version             ='0.5.0',
    description         ='A multiprocessing async ping scanner',
    author              ='Itzik Grossman',
    author_email        ='itzygro@gmail.com',
    python_requires     =">=3.6",
    license             ='MIT License',
    classifiers         =[
        'Programming Language :: Python',
        'Natural Language :: English',
        'Environment :: Plugins',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Topic :: System :: Monitoring',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
