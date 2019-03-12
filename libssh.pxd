
# python-libssh -- Python bindings to client functionality of libssh
# Copyright (C) 2019 Jan Pazdziora
# This library is distributed under the terms of LGPL 2.1,
# see file COPYING in this repository.

cdef extern from "libssh/libssh.h" nogil:

	cpdef const char * LIBSSH_VERSION "SSH_STRINGIFY(LIBSSH_VERSION)"

	cdef int SSH_OK
	cdef int SSH_ERROR

	const char * ssh_get_error(void *)
	void ssh_string_free_char(char *)

	struct ssh_session_struct:
		pass
	ctypedef ssh_session_struct * ssh_session

	ssh_session ssh_new()
	void ssh_free(ssh_session)

	int ssh_connect(ssh_session)
	int ssh_is_connected(ssh_session)
	void ssh_disconnect(ssh_session)

	cdef enum ssh_options_e:
		SSH_OPTIONS_HOST,
		SSH_OPTIONS_PORT

	int ssh_options_get(ssh_session, ssh_options_e, char **)
	int ssh_options_get_port(ssh_session, unsigned int *)
	int ssh_options_set(ssh_session, ssh_options_e, const void *)

cdef class Session:
	cdef ssh_session _libssh_session

