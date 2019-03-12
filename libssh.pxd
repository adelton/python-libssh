
# python-libssh -- Python bindings to client functionality of libssh
# Copyright (C) 2019 Jan Pazdziora
# This library is distributed under the terms of LGPL 2.1,
# see file COPYING in this repository.

cdef extern from "libssh/libssh.h" nogil:

	cpdef const char * LIBSSH_VERSION "SSH_STRINGIFY(LIBSSH_VERSION)"

	cdef int SSH_OK
	cdef int SSH_ERROR

