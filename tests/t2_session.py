
import unittest
import subprocess
from os import unlink
import libssh

class SessionTest(unittest.TestCase):

	def test1_session_host(self):
		session = libssh.Session()
		self.assertIsNotNone(session)
		self.assertIsInstance(session, libssh.Session)
		self.assertIsNone(session.host)
		with self.assertRaises(libssh.libsshException) as cm:
			session.connect()
		self.assertEqual(str(cm.exception), "Hostname required")
		session.host = "unknown-localhost"
		self.assertEqual(session.host, "unknown-localhost")
		with self.assertRaises(libssh.libsshException) as cm:
			session.connect()
		self.assertEqual(str(cm.exception), "Failed to resolve hostname unknown-localhost (Name or service not known)")

	def test2_session_port(self):
		session = libssh.Session()
		self.assertIsInstance(session, libssh.Session)
		session.host = "localhost"
		self.assertEqual(session.host, "localhost")
		self.assertEqual(session.port, 22)
		session.port = 122
		self.assertEqual(session.port, 122)
		with self.assertRaises(libssh.libsshException) as cm:
			session.connect()
		self.assertEqual(str(cm.exception), "Connection refused")

	def test3_session_options(self):
		session = libssh.Session("unknown-localhost")
		self.assertEqual(session.host, "unknown-localhost")
		self.assertEqual(session.port, 22)

		session = libssh.Session("unknown-localhost", port=222)
		self.assertEqual(session.host, "unknown-localhost")
		self.assertEqual(session.port, 222)

		session = libssh.Session(host="unknown-localhost", port=222)
		self.assertEqual(session.host, "unknown-localhost")
		self.assertEqual(session.port, 222)
		self.assertIsNone(session.knownhosts)

		session = libssh.Session(port=222, knownhosts="/dev/null")
		self.assertIsNone(session.host)
		self.assertEqual(session.port, 222)
		self.assertEqual(session.knownhosts, "/dev/null")

		session = libssh.Session(ssh_dir="/dev/null", user="bob")
		self.assertEqual(session.ssh_dir, "/dev/null")
		self.assertEqual(session.user, "bob")

		session = libssh.Session(ssh_dir="/dev/null", add_identity="./testkey")
		self.assertEqual(session.ssh_dir, "/dev/null")
		self.assertEqual(session.add_identity, "./testkey")

	def test4_session_ok(self):
		session = libssh.Session()
		self.assertIsInstance(session, libssh.Session)
		session.host = "localhost"
		session.connect()
		self.assertTrue(session.is_connected())
		session.disconnect()
		self.assertFalse(session.is_connected())
		session.disconnect()
		self.assertFalse(session.is_connected())

	def test5_session_unknown(self):
		session = libssh.Session()
		self.assertIsInstance(session, libssh.Session)
		session.host = "localhost"
		self.assertIsNone(session.knownhosts)
		session.knownhosts = "/dev/null"
		self.assertEqual(session.knownhosts, "/dev/null")
		with self.assertRaises(libssh.libsshException) as cm:
			session.connect()
		self.assertRegex(str(cm.exception), r"Host is unknown: ([0-9a-f][0-9a-z]:){19}[0-9a-f][0-9a-z]$")
		self.assertFalse(session.is_connected())

	def test6_session_connect_options(self):
		session = libssh.Session(port = 122)
		self.assertIsInstance(session, libssh.Session)
		session.host = "localhost"
		session.connect("localhost", port = 22)
		self.assertTrue(session.is_connected())
		session.disconnect()
		self.assertFalse(session.is_connected())

	def test9_session_auth(self):
		# check that authentication to our account on locahost works
		ssh_ext = subprocess.run(["ssh", "localhost", "exit", "42"])
		self.assertIsNotNone(ssh_ext)
		self.assertIsInstance(ssh_ext, subprocess.CompletedProcess)
		self.assertEqual(ssh_ext.returncode, 42)

		session = libssh.Session()
		self.assertIsInstance(session, libssh.Session)
		session.host = "localhost"
		session.connect()
		# now authenticate via libssh (pubkey)
		session.authenticate_pubkey()
		self.assertTrue(session.is_connected())
		session.disconnect()

		for f in (".testkey", ".testkey.pub"):
			try: unlink(f)
			except FileNotFoundError:
				pass
		ssh_keygen = subprocess.run(["ssh-keygen", "-N", "", "-f", ".testkey"], stdout=subprocess.PIPE)
		self.assertIsInstance(ssh_keygen, subprocess.CompletedProcess)
		session = libssh.Session(host="localhost", ssh_dir=".", add_identity=".testkey")
		session.knownhosts = "~/.ssh/known_hosts"
		session.connect()
		# now authenticate via the fresh key, should fail
		with self.assertRaises(libssh.libsshException) as cm:
			session.authenticate_pubkey()
		self.assertRegex(str(cm.exception), r"^Access denied for 'publickey'\. Authentication that can continue:")

if __name__ == '__main__':
	unittest.main()

