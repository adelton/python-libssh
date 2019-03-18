
# python-libssh -- Python bindings to client functionality of libssh
# Copyright (C) 2019 Jan Pazdziora
# This library is distributed under the terms of LGPL 2.1,
# see file COPYING in this repository.

cimport libssh
from cpython.bytes cimport PyBytes_AS_STRING
from libc.stdint cimport uint32_t
from libc.string cimport memset
from posix.fcntl cimport O_WRONLY, O_CREAT, O_TRUNC
from subprocess import CalledProcessError, CompletedProcess

version = LIBSSH_VERSION.decode("ascii")

cdef class libsshException(Exception):
	def __init__(self, object):
		if not isinstance(object, unicode):
			object = object._get_error_str()
		super().__init__(object)

cdef int _process_outputs(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata):
	if len == 0:
		return 0
	data_b = <bytes>(<char *>data)[:len]
	result = <object>userdata
	if is_stderr:
		result.stderr += data_b
	else:
		result.stdout += data_b
	return len

cdef class Session:
	def __cinit__(self, host=None, **kwargs):
		self._libssh_session = ssh_new()
		if self._libssh_session is NULL:
			raise MemoryError
		self._opts = {}
		if host:
			self.host = host
		for key in kwargs:
			self.__setattr__(key, kwargs[key])

	def __dealloc__(self):
		if self._libssh_session is not NULL:
			if ssh_is_connected(self._libssh_session):
				ssh_disconnect(self._libssh_session)
			ssh_free(self._libssh_session)
			self._libssh_session = NULL

	def _get_error_str(self):
		return ssh_get_error(self._libssh_session).decode()

	@property
	def port(self):
		cdef unsigned int port_i
		if ssh_options_get_port(self._libssh_session, &port_i) != SSH_OK:
			return None
		return port_i

	opts_map = {
		"host": SSH_OPTIONS_HOST,
		"knownhosts": SSH_OPTIONS_KNOWNHOSTS,
		"port": SSH_OPTIONS_PORT,
		"user": SSH_OPTIONS_USER,
	}
	opts_dir_map = {
		"ssh_dir": SSH_OPTIONS_SSH_DIR,
		"add_identity": SSH_OPTIONS_ADD_IDENTITY,
	}
	def __getattr__(self, key):
		if not key in type(self).opts_map:
			if key in type(self).opts_dir_map:
				return self._opts[key]
			raise libsshException("Unknown attribute name [%s]" % key)
		cdef char * value
		if ssh_options_get(self._libssh_session, type(self).opts_map[key], &value) != SSH_OK:
			return None
		ret = value.decode()
		ssh_string_free_char(value)
		return ret

	def __setattr__(self, key, value):
		cdef unsigned int port_i
		key_m = None
		if key in type(self).opts_dir_map:
			key_m = type(self).opts_dir_map[key]
		elif key in type(self).opts_map:
			key_m = type(self).opts_map[key]
		else:
			raise libsshException("Unknown attribute name [%s]" % key)
		if key == "port":
			port_i = value
			ssh_options_set(self._libssh_session, SSH_OPTIONS_PORT, &port_i)
		else:
			ssh_options_set(self._libssh_session, key_m, PyBytes_AS_STRING(value.encode("utf-8")))
			if key in type(self).opts_dir_map:
				self._opts[key] = value

	def connect(self, host=None, **kwargs):
		if host:
			self.host = host
		for key in kwargs:
			self.__setattr__(key, kwargs[key])
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
		cdef ssh_key srv_pubkey = NULL
		cdef unsigned char * hash = NULL
		cdef size_t hash_len
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

	def authenticate_pubkey(self):
		if ssh_userauth_publickey_auto(self._libssh_session, NULL, NULL) != SSH_AUTH_SUCCESS:
			raise libsshException(self)

	def run(self, command):
		cdef ssh_channel channel = ssh_channel_new(self._libssh_session)
		if channel is NULL:
			raise MemoryError
		rc = ssh_channel_open_session(channel)
		if rc != SSH_OK:
			ssh_channel_free(channel)
			raise CalledProcessError()

		rc = ssh_channel_request_exec(channel, command.encode("utf-8"))
		if rc != SSH_OK:
			ssh_channel_close(channel)
			ssh_channel_free(channel)
			raise CalledProcessError()

		cdef ssh_channel_callbacks_struct cb
		memset(&cb, 0, sizeof(cb))
		cb.channel_data_function = <ssh_channel_data_callback>&_process_outputs
		result = CompletedProcess(args = command, returncode = -1, stdout = b'', stderr = b'')
		cb.userdata = <void *>result
		ssh_callbacks_init(&cb)
		ssh_set_channel_callbacks(channel, &cb)

		ssh_channel_send_eof(channel)
		result.returncode = ssh_channel_get_exit_status(channel)

		ssh_channel_close(channel)
		ssh_channel_free(channel)

		return result

	def new_channel(self):
		return Channel(self)

	def new_shell_channel(self):
		channel = Channel(self)
		channel.request_shell()
		return channel

	def sftp(self):
		return SFTP(self)

cdef ssh_session _get_libssh_session(Session session):
	return session._libssh_session

cdef class Channel:
	def __cinit__(self, session):
		self._libssh_channel = ssh_channel_new(_get_libssh_session(session))
		if self._libssh_channel is NULL:
			raise MemoryError
		rc = ssh_channel_open_session(self._libssh_channel)
		if rc != SSH_OK:
			self._libssh_channel = NULL
			ssh_channel_free(self._libssh_channel)
			raise libsshException("Failed to open_session: [%d]" % rc)

	def __dealloc__(self):
		if self._libssh_channel is NULL:
			ssh_channel_close(self._libssh_channel)
			ssh_channel_free(self._libssh_channel)
			self._libssh_channel = NULL

	def request_shell(self):
		rc = ssh_channel_request_shell(self._libssh_channel)
		if rc != SSH_OK:
			raise libsshException("Failed to request_shell: [%d]" % rc)

	def read_nonblocking(self, size=1024, stderr=0):
		cdef char buffer[1024]
		size_m = size
		if size_m > sizeof(buffer):
			size_m = sizeof(buffer)
		nbytes = ssh_channel_read_nonblocking(self._libssh_channel, buffer, size_m, stderr)
		return <bytes>buffer[:nbytes]

	def write(self, data):
		return ssh_channel_write(self._libssh_channel, PyBytes_AS_STRING(data), len(data))

cdef class libsshSFTPException(libsshException):
	def __init__(self, object, message):
		super().__init__(message + ": " + object._get_error_str())

cdef class SFTP:
	def __cinit__(self, session):
		self.session = session
		self._libssh_sftp_session = sftp_new(_get_libssh_session(session))
		if self._libssh_sftp_session is NULL:
			raise libsshException(session)
		if sftp_init(self._libssh_sftp_session) != SSH_OK:
			raise libsshSFTPException(self, "Error initializing SFTP session")

	def __dealloc__(self):
		if self._libssh_sftp_session is not NULL:
			sftp_free(self._libssh_sftp_session)
			self._libssh_sftp_session = NULL

	def _get_error_str(self):
		return self.session._get_error_str()

	def put(self, local_file, remote_file):
		cdef sftp_file rf
		with open(local_file, "rb") as f:
			remote_file_b = remote_file
			if isinstance(remote_file_b, unicode):
				remote_file_b = remote_file.encode("utf-8")
			rf = sftp_open(self._libssh_sftp_session, remote_file_b, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU)
			if rf is NULL:
				raise libsshSFTPException(self, "Opening remote file [%s] for write failed" % remote_file)
			buffer = f.read(1024)
			while buffer != b"":
				length = len(buffer)
				written = sftp_write(rf, PyBytes_AS_STRING(buffer), length)
				if written != length:
					sftp_close(rf)
					raise libsshSFTPException(self, "Writing to remote file [%s] failed" % remote_file)
				buffer = f.read(1024)
			sftp_close(rf)

