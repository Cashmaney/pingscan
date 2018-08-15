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

setup(install_requires=REQUIRES,
    cmdclass={"build_ext": build_ext},
    ext_modules = EXTENSIONS
)
