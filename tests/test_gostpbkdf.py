import unittest
import os
import pytest
from unittest import mock

import gostcrypto
from gostcrypto.gostpbkdf import GOSTPBKDFError

TEST_PASSWORD = b'password'
TEST_SALT = b'salt'
TEST_DK_1 = bytearray.fromhex('64770af7f748c3b1c9ac831dbcfd85c26111b30a8a657ddc3056b80ca73e040d2854fd36811f6d825cc4ab66ec0a68a490a9e5cf5156b3a2b7eecddbf9a16b47')
TEST_DK_2 = bytearray.fromhex('5a585bafdfbb6e8830d6d68aa3b43ac00d2e4aebce01c9b31c2caed56f0236d4d34b2b8fbd2c4e89d54d46f50e47d45bbac301571743119e8d3c42ba66d348de')
TEST_DK_SHOT = bytearray.fromhex('64770af7f748c3b1c9ac831dbcfd85c26111b30a8a657ddc3056b80ca73e040d')

def os_urandom(value):
    return TEST_SALT

@pytest.mark.pbkdf
class TestPBKDF(unittest.TestCase):

    def test_pbcdf_derive_1(self):
        test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt=TEST_SALT, counter=1)
        self.assertEqual(test_pbkdf.derive(64), TEST_DK_1)
        test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt=TEST_SALT, counter=1)
        self.assertEqual(test_pbkdf.hexderive(64), TEST_DK_1.hex())

    def test_pbcdf_derive_2(self):
        test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt=TEST_SALT, counter=2)
        self.assertEqual(test_pbkdf.derive(64), TEST_DK_2)
        test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt=TEST_SALT, counter=2)
        self.assertEqual(test_pbkdf.hexderive(64), TEST_DK_2.hex())

    def test_pbcdf_derive_shot(self):
        test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt=TEST_SALT, counter=1)
        self.assertEqual(test_pbkdf.derive(32), TEST_DK_SHOT)
        test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt=TEST_SALT, counter=1)
        self.assertEqual(test_pbkdf.hexderive(32), TEST_DK_SHOT.hex())

    def test_pbcdf_derive_raises(self):
        test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt=TEST_SALT, counter=1)
        with self.assertRaises(GOSTPBKDFError) as context:
            test_pbkdf.derive(((2 ** 32 - 1) * 64) + 1)
        self.assertTrue('invalid size of the derived key' in str(context.exception))
        test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt=TEST_SALT, counter=1)
        with self.assertRaises(GOSTPBKDFError) as context:
            test_pbkdf.hexderive(((2 ** 32 - 1) * 64) + 1)
        self.assertTrue('invalid size of the derived key' in str(context.exception))

    def test_pbcdf_raises(self):
        with self.assertRaises(GOSTPBKDFError) as context:
            test_pbkdf = gostcrypto.gostpbkdf.new('test_password', salt=TEST_SALT, counter=1)
        self.assertTrue('invalid password value' in str(context.exception))
        with self.assertRaises(GOSTPBKDFError) as context:
            test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt='test_salt', counter=1)
        self.assertTrue('invalid salt value' in str(context.exception))

    def test_pbcdf_salt(self):
        test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt=TEST_SALT, counter=1)
        self.assertEqual(test_pbkdf.salt, TEST_SALT)

    def test_pbkdf_urandom(self):
        with mock.patch('os.urandom', os_urandom):
            test_pbkdf = gostcrypto.gostpbkdf.new(TEST_PASSWORD, salt=b'', counter=1)
        self.assertEqual(test_pbkdf.derive(32), TEST_DK_SHOT)
