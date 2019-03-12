
# python-libssh -- Python bindings to client functionality of libssh
# Copyright (C) 2019 Jan Pazdziora
# This library is distributed under the terms of LGPL 2.1,
# see file COPYING in this repository.

cimport libssh
from cpython.bytes cimport PyBytes_AS_STRING

version = LIBSSH_VERSION.decode("ascii")

cdef class libsshException(Exception):
	def __init__(self, object):
		if not isinstance(object, unicode):
			object = object._get_error_str()
		super().__init__(object)

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

	@property
	def knownhosts(self):
		cdef char * value
		if ssh_options_get(self._libssh_session, SSH_OPTIONS_KNOWNHOSTS, &value) != SSH_OK:
			return None
		ret = value.decode()
		ssh_string_free_char(value)
		return ret
	@knownhosts.setter
	def knownhosts(self, unicode value):
		ssh_options_set(self._libssh_session, SSH_OPTIONS_KNOWNHOSTS, PyBytes_AS_STRING(value.encode("utf-8")))

	def connect(self):
		if ssh_connect(self._libssh_session) != SSH_OK:
			ssh_disconnect(self._libssh_session)
			raise libsshException(self)
		try:
			self.verify_knownhost()
		except Exception:
			ssh_disconnect(self._libssh_session)
			raise

	def is_connected(self):
		return self._libssh_session is not NULL and ssh_is_connected(self._libssh_session)

	def disconnect(self):
		ssh_disconnect(self._libssh_session)

	def get_server_publickey(self):
		cdef ssh_key srv_pubkey = NULL;
		cdef unsigned char * hash = NULL;
		cdef size_t hash_len;
		if ssh_get_server_publickey(self._libssh_session, &srv_pubkey) != SSH_OK:
			return None
		rc = ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash, &hash_len)
		ssh_key_free(srv_pubkey)
		if rc != SSH_OK:
			return None
		cdef char * hash_hex = ssh_get_hexa(hash, hash_len)
		hash_py = hash_hex.decode("ascii")
		ssh_string_free_char(hash_hex)
		return hash_py

	def verify_knownhost(self):
		cdef ssh_known_hosts_e state = ssh_session_is_known_server(self._libssh_session)
		if state == SSH_KNOWN_HOSTS_OK:
			return True
		hash = self.get_server_publickey()
		if state == SSH_KNOWN_HOSTS_ERROR:
			raise libsshException(self)
		msg_map = {
			SSH_KNOWN_HOSTS_CHANGED: "Host key for server has changed: " + hash,
			SSH_KNOWN_HOSTS_OTHER: "Host key type for server has changed: " + hash,
			SSH_KNOWN_HOSTS_NOT_FOUND: "Host file not found",
			SSH_KNOWN_HOSTS_UNKNOWN: "Host is unknown: " + hash,
		}
		raise libsshException(msg_map[state])

