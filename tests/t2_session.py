
import unittest
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

	def test3_session_ok(self):
		session = libssh.Session()
		self.assertIsInstance(session, libssh.Session)
		session.host = "localhost"
		session.connect()
		self.assertTrue(session.is_connected())
		session.disconnect()
		self.assertFalse(session.is_connected())
		session.disconnect()
		self.assertFalse(session.is_connected())

