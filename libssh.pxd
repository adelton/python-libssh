
# python-libssh -- Python bindings to client functionality of libssh
# Copyright (C) 2019 Jan Pazdziora
# This library is distributed under the terms of LGPL 2.1,
# see file COPYING in this repository.

from libc.stdint cimport uint32_t
from posix.types cimport mode_t

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

	struct ssh_channel_struct:
		pass
	ctypedef ssh_channel_struct * ssh_channel

	ssh_channel ssh_channel_new(ssh_session)
	void ssh_channel_free(ssh_channel)

	int ssh_channel_open_session(ssh_channel)
	int ssh_channel_request_shell(ssh_channel)
	int ssh_channel_is_open(ssh_channel)
	int ssh_channel_read_nonblocking(ssh_channel, void *, uint32_t, int)
	int ssh_channel_close(ssh_channel)

	int ssh_channel_request_exec(ssh_channel, const char *)
	int ssh_channel_get_exit_status(ssh_channel)

	int ssh_channel_send_eof(ssh_channel)

cdef extern from "libssh/callbacks.h" nogil:

	void ssh_callbacks_init(void *)

	ctypedef int (*ssh_channel_data_callback) (ssh_session session, ssh_channel channel,
					void *data, uint32_t len, int is_stderr, void *userdata)
	ctypedef void (*ssh_channel_eof_callback) (ssh_session session, ssh_channel channel, void *userdata)
	ctypedef void (*ssh_channel_close_callback) (ssh_session session, ssh_channel channel, void *userdata)
	ctypedef void (*ssh_channel_signal_callback) (ssh_session session, ssh_channel channel,
							const char *signal, void *userdata)
	ctypedef void (*ssh_channel_exit_status_callback) (ssh_session session, ssh_channel channel,
							int exit_status, void *userdata)
	ctypedef void (*ssh_channel_exit_signal_callback) (ssh_session session, ssh_channel channel,
			const char *signal, int core, const char *errmsg, const char *lang, void *userdata)
	ctypedef int (*ssh_channel_pty_request_callback) (ssh_session session, ssh_channel channel,
		const char *term, int width, int height, int pxwidth, int pwheight, void *userdata)
	ctypedef int (*ssh_channel_shell_request_callback) (ssh_session session, ssh_channel channel, void *userdata)
	ctypedef void (*ssh_channel_auth_agent_req_callback) (ssh_session session, ssh_channel channel, void *userdata)
	ctypedef void (*ssh_channel_x11_req_callback) (ssh_session session, ssh_channel channel,
		int single_connection, const char *auth_protocol, const char *auth_cookie, uint32_t screen_number,
		void *userdata)
	ctypedef int (*ssh_channel_pty_window_change_callback) (ssh_session session, ssh_channel channel,
				int width, int height, int pxwidth, int pwheight, void *userdata)
	ctypedef int (*ssh_channel_exec_request_callback) (ssh_session session, ssh_channel channel,
					const char *command, void *userdata)
	ctypedef int (*ssh_channel_env_request_callback) (ssh_session session, ssh_channel channel,
					const char *env_name, const char *env_value, void *userdata)
	ctypedef int (*ssh_channel_subsystem_request_callback) (ssh_session session, ssh_channel channel,
					const char *subsystem, void *userdata)
	ctypedef int (*ssh_channel_write_wontblock_callback) (ssh_session session, ssh_channel channel,
					size_t bytes, void *userdata)

	struct ssh_channel_callbacks_struct:
		size_t size
		void *userdata
		ssh_channel_data_callback channel_data_function
		ssh_channel_eof_callback channel_eof_function
		ssh_channel_close_callback channel_close_function
		ssh_channel_signal_callback channel_signal_function
		ssh_channel_exit_status_callback channel_exit_status_function
		ssh_channel_exit_signal_callback channel_exit_signal_function
		ssh_channel_pty_request_callback channel_pty_request_function
		ssh_channel_shell_request_callback channel_shell_request_function
		ssh_channel_auth_agent_req_callback channel_auth_agent_req_function
		ssh_channel_x11_req_callback channel_x11_req_function
		ssh_channel_pty_window_change_callback channel_pty_window_change_function
		ssh_channel_exec_request_callback channel_exec_request_function
		ssh_channel_env_request_callback channel_env_request_function
		ssh_channel_subsystem_request_callback channel_subsystem_request_function
		ssh_channel_write_wontblock_callback channel_write_wontblock_function
	ctypedef ssh_channel_callbacks_struct * ssh_channel_callbacks

	int ssh_set_channel_callbacks(ssh_channel, ssh_channel_callbacks)

cdef extern from "sys/stat.h" nogil:

	cdef int S_IRWXU

cdef extern from "libssh/sftp.h" nogil:

	struct sftp_session_struct:
		pass
	ctypedef sftp_session_struct * sftp_session

	sftp_session sftp_new(ssh_session)
	int sftp_init(sftp_session)
	void sftp_free(sftp_session)

	struct sftp_file_struct:
		pass
	ctypedef sftp_file_struct * sftp_file

	sftp_file sftp_open(sftp_session, const char *, int, mode_t)
	int sftp_close(sftp_file)
	ssize_t sftp_write(sftp_file, const void *, size_t)

cdef class Session:
	cdef ssh_session _libssh_session
	cdef _opts

cdef class Channel:
	cdef ssh_channel _libssh_channel

cdef class SFTP:
	cdef Session session
	cdef sftp_session _libssh_sftp_session

