
import unittest
import subprocess
import libssh

class VersionTest(unittest.TestCase):

	def test_version(self):
		rpm_q_libssh = subprocess.run(["rpm", "-q", "--qf", "%{version}", "libssh"], stdout=subprocess.PIPE)
		self.assertIsNotNone(rpm_q_libssh)
		self.assertIsInstance(rpm_q_libssh, subprocess.CompletedProcess)
		self.assertIsNotNone(rpm_q_libssh.stdout)
		self.assertEqual(libssh.version, rpm_q_libssh.stdout.decode())

if __name__ == '__main__':
	unittest.main()

