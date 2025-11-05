
import unittest
import subprocess
from contextlib import contextmanager
import sys
import os
from time import sleep
import libssh

class ShellTest(unittest.TestCase):

	def test1_shell(self):
		session = libssh.Session(host = "localhost")
		self.assertIsInstance(session, libssh.Session)
		session.connect()
		session.authenticate_pubkey()
		self.assertTrue(session.is_connected())

		channel = session.new_shell_channel()
		self.assertIsInstance(channel, libssh.Channel)

		data = channel.read_nonblocking()
		self.assertRegex(data.decode('utf-8'), r"^$|^Last login: ")
		sleep(1)
		data = channel.read_nonblocking()
		self.assertRegex(data.decode('utf-8'), r"^Last login: |\[root@.+ ~\]# $")

		channel.write(b"echo hello world\n")
		sleep(1)
		data = channel.read_nonblocking()
		self.assertRegex(data.decode('utf-8'), r"^echo hello world\r\n(\033]3008;start=.*?\033\\)?hello world\r\n")

		session.disconnect()

if __name__ == '__main__':
	unittest.main()

