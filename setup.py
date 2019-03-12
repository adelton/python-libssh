
# python-libssh -- Python bindings to client functionality of libssh
# Copyright (C) 2019 Jan Pazdziora
# This library is distributed under the terms of LGPL 2.1,
# see file COPYING in this repository.

from setuptools import setup
from setuptools.extension import Extension
from Cython.Build import cythonize

import unittest
def get_tests():
	return unittest.TestLoader().discover("tests", pattern="*.py")

setup(
	name = "python-libssh",
	version = "0.0.1",
	description = "Python bindings to client functionality of libssh",
	ext_modules = cythonize([Extension("libssh", ["libssh.pyx"],
							libraries=["ssh"])]),
	classifiers = [
		"Development Status :: 2 - Pre-Alpha",
		"License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)",
		"Topic :: Security",
	],
	test_suite = "setup.get_tests",
)

