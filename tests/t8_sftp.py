
import unittest
from os import getcwd, path, unlink
from filecmp import cmp
import libssh

class SFTPTest(unittest.TestCase):

	def test1_put(self):
		session = libssh.Session(host = "localhost")
		self.assertIsInstance(session, libssh.Session)
		session.connect()
		session.authenticate_pubkey()
		self.assertTrue(session.is_connected())

		sftp = session.sftp()
		in_file = ".testfile.in"
		with open(in_file, "wb") as f:
			for i in range(1, 1000):
				f.write(b"%d\n" % i)

		out_file = path.join(getcwd(), ".testfile.out")
		try: unlink(out_file)
		except FileNotFoundError:
			pass
		sftp.put(in_file, out_file)
		self.assertTrue(cmp(in_file, out_file, shallow=False))
		# session.disconnect()

		# out_file = "/jezek/.testfile.out"

	def test1_put_filename_bytes(self):
		session = libssh.Session(host = "localhost")
		self.assertIsInstance(session, libssh.Session)
		session.connect()
		session.authenticate_pubkey()
		self.assertTrue(session.is_connected())

		sftp = session.sftp()
		in_file = b".testfile.in"
		with open(in_file, "wb") as f:
			for i in range(1, 1000):
				f.write(b"%d\n" % i)

		out_file = path.join(getcwd(), ".testfile.out").encode("utf-8")
		try: unlink(out_file)
		except FileNotFoundError:
			pass
		sftp.put(in_file, out_file)
		self.assertTrue(cmp(in_file, out_file, shallow=False))
		# session.disconnect()

		# out_file = "/jezek/.testfile.out"

if __name__ == '__main__':
	unittest.main()

