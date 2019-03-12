
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

	cdef enum ssh_known_hosts_e:
		SSH_KNOWN_HOSTS_ERROR,
		SSH_KNOWN_HOSTS_NOT_FOUND,
		SSH_KNOWN_HOSTS_UNKNOWN,
		SSH_KNOWN_HOSTS_OK,
		SSH_KNOWN_HOSTS_CHANGED,
		SSH_KNOWN_HOSTS_OTHER

	ssh_known_hosts_e ssh_session_is_known_server(ssh_session)

	cdef enum ssh_options_e:
		SSH_OPTIONS_HOST,
		SSH_OPTIONS_PORT,
		SSH_OPTIONS_KNOWNHOSTS,
		SSH_OPTIONS_USER,
		SSH_OPTIONS_SSH_DIR,
		SSH_OPTIONS_ADD_IDENTITY,

	int ssh_options_get(ssh_session, ssh_options_e, char **)
	int ssh_options_get_port(ssh_session, unsigned int *)
	int ssh_options_set(ssh_session, ssh_options_e, const void *)

	struct ssh_key_struct:
		pass
	ctypedef ssh_key_struct * ssh_key

	int ssh_get_server_publickey(ssh_session, ssh_key *)
	void ssh_key_free(ssh_key)

	cdef enum ssh_publickey_hash_type:
		SSH_PUBLICKEY_HASH_SHA1,
		SSH_PUBLICKEY_HASH_SHA256

	int ssh_get_publickey_hash(const ssh_key, ssh_publickey_hash_type, unsigned char **, size_t *)
	char * ssh_get_hexa(const unsigned char *, size_t)

	cdef enum ssh_auth_e:
		SSH_AUTH_SUCCESS,
		SSH_AUTH_DENIED,
		SSH_AUTH_PARTIAL,
		SSH_AUTH_INFO,
		SSH_AUTH_AGAIN,
		SSH_AUTH_ERROR

	int ssh_userauth_publickey_auto(ssh_session, const char *, const char *)

cdef class Session:
	cdef ssh_session _libssh_session
	cdef _opts

