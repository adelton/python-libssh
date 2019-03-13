
import unittest
import subprocess
from contextlib import contextmanager
import sys
import os
import libssh

@contextmanager
def redirect_output(stdout, stderr):
	stdout_orig = os.dup(1)
	stderr_orig = os.dup(2)
	try:
		os.dup2(stdout, sys.stdout.fileno())
		os.dup2(stderr, sys.stderr.fileno())
		yield
	finally:
		os.dup2(stdout_orig, 1)
		os.dup2(stderr_orig, 2)

class CommandTest(unittest.TestCase):

	def test1_subprocess(self):
		stdout = os.pipe()
		stderr = os.pipe()
		with redirect_output(stdout[1], stderr[1]):
			proc = subprocess.run("echo stdout-data; echo stderr-data >&2; exit 42", shell=True)
		self.assertIsInstance(proc, subprocess.CompletedProcess)
		self.assertEqual(proc.returncode, 42)
		self.assertIsNone(proc.stdout)
		self.assertIsNone(proc.stderr)
		self.assertEqual(os.read(stdout[0], 1024), b"stdout-data\n")
		self.assertEqual(os.read(stderr[0], 1024), b"stderr-data\n")

		proc = subprocess.run("echo stdout-data; echo stderr-data >&2; exit 42",
			shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.assertIsInstance(proc, subprocess.CompletedProcess)
		self.assertEqual(proc.returncode, 42)
		self.assertEqual(proc.stdout, b"stdout-data\n")
		self.assertEqual(proc.stderr, b"stderr-data\n")

		proc = subprocess.run("echo stdout-data; echo stderr-data >&2; exit 42",
			shell=True, encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.assertIsInstance(proc, subprocess.CompletedProcess)
		self.assertEqual(proc.returncode, 42)
		self.assertEqual(proc.stdout, "stdout-data\n")
		self.assertEqual(proc.stderr, "stderr-data\n")

	def test2_command(self):
		session = libssh.Session(host = "localhost")
		self.assertIsInstance(session, libssh.Session)
		session.connect()
		session.authenticate_pubkey()
		self.assertTrue(session.is_connected())

		command_finished = session.run("echo stdout-data; echo stderr-data >&2; exit 42")
		self.assertIsInstance(command_finished, subprocess.CompletedProcess)
		self.assertEqual(command_finished.returncode, 42)
		self.assertEqual(command_finished.stdout, b"stdout-data\n")
		self.assertEqual(command_finished.stderr, b"stderr-data\n")
		session.disconnect()

