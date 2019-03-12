
# python-libssh -- Python bindings to client functionality of libssh
# Copyright (C) 2019 Jan Pazdziora
# This library is distributed under the terms of LGPL 2.1,
# see file COPYING in this repository.

cimport libssh
from cpython.bytes cimport PyBytes_AS_STRING

version = LIBSSH_VERSION.decode("ascii")

cdef class libsshException(Exception):
	def __init__(self, object):
		super().__init__(object._get_error_str())

cdef class Session:
	def __cinit__(self):
		self._libssh_session = ssh_new()
		if self._libssh_session is NULL:
			raise MemoryError

	def __dealloc__(self):
		if self._libssh_session is not NULL:
			if ssh_is_connected(self._libssh_session):
				ssh_disconnect(self._libssh_session)
			ssh_free(self._libssh_session)
			self._libssh_session = NULL

	def _get_error_str(self):
		return ssh_get_error(self._libssh_session).decode()

	@property
	def host(self):
		cdef char * value
		if ssh_options_get(self._libssh_session, SSH_OPTIONS_HOST, &value) != SSH_OK:
			return None
		ret = value.decode()
		ssh_string_free_char(value)
		return ret
	@host.setter
	def host(self, unicode value):
		ssh_options_set(self._libssh_session, SSH_OPTIONS_HOST, PyBytes_AS_STRING(value.encode("utf-8")))

	@property
	def port(self):
		cdef unsigned int port_i
		if ssh_options_get_port(self._libssh_session, &port_i) != SSH_OK:
			return None
		return port_i
	@port.setter
	def port(self, int value):
		ssh_options_set(self._libssh_session, SSH_OPTIONS_PORT, &value)

	def connect(self):
		if ssh_connect(self._libssh_session) != SSH_OK:
			ssh_disconnect(self._libssh_session)
			raise libsshException(self)

	def is_connected(self):
		return self._libssh_session is not NULL and ssh_is_connected(self._libssh_session)

	def disconnect(self):
		ssh_disconnect(self._libssh_session)

