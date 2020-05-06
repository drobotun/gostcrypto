import unittest
import pytest

import gostcrypto
from gostcrypto.gosthmac import GOSTHMACError

TEST_KEY = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
TEST_DATA = bytearray.fromhex('0126bdb87800af214341456563780100')
TEST_HMAC_256 = bytearray.fromhex('a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9')
TEST_HMAC_512 = bytearray.fromhex('a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6')
TEST_HMAC_256_DOUBLE_UPDATE = bytearray.fromhex('7c3f66aacd8015751cd8c4735819dfa3a2ec36d89c241c6551878c37c84b092e')

@pytest.mark.hmac
class TestHMAC(unittest.TestCase):

    def test_digest_256(self):
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', TEST_KEY)
        test_hmac.update(TEST_DATA)
        self.assertEqual(test_hmac.digest(), TEST_HMAC_256)

    def test_digest_512(self):
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', TEST_KEY)
        test_hmac.update(TEST_DATA)
        self.assertEqual(test_hmac.digest(), TEST_HMAC_512)

    def test_hexdigest_256(self):
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', TEST_KEY)
        test_hmac.update(TEST_DATA)
        self.assertEqual(test_hmac.hexdigest(), TEST_HMAC_256.hex())

    def test_hexdigest_512(self):
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', TEST_KEY)
        test_hmac.update(TEST_DATA)
        self.assertEqual(test_hmac.hexdigest(), TEST_HMAC_512.hex())

    def test_copy(self):
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', TEST_KEY)
        test_hmac_copy = test_hmac.copy()
        test_hmac_copy.update(TEST_DATA)
        self.assertEqual(test_hmac_copy.hexdigest(), TEST_HMAC_512.hex())

    def test_name(self):
        test_hmac_512 = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', TEST_KEY)
        self.assertEqual(test_hmac_512.name, 'HMAC_GOSTR3411_2012_512')
        test_hmac_256 = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', TEST_KEY)
        self.assertEqual(test_hmac_256.name, 'HMAC_GOSTR3411_2012_256')

    def test_digest_size(self):
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', TEST_KEY)
        self.assertEqual(test_hmac.digest_size, 64)
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', TEST_KEY)
        self.assertEqual(test_hmac.digest_size, 32)

    def test_block_size(self):
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', TEST_KEY)
        self.assertEqual(test_hmac.block_size, 64)

    def test_key_value_raises(self):
        add = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff')
        with self.assertRaises(GOSTHMACError) as context:
            test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', TEST_KEY + add)
        self.assertTrue('invalid key value' in str(context.exception))

    def test_data_value_raises(self):
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', TEST_KEY)
        with self.assertRaises(GOSTHMACError) as context:
            test_hmac.update('test_data')
        self.assertTrue('invalid data value' in str(context.exception))

    def test_key_512(self):
        add = bytearray(32)
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', TEST_KEY + add)
        test_hmac.update(TEST_DATA)
        self.assertEqual(test_hmac.digest(), TEST_HMAC_512)

    def test_hmac_raises(self):
        with self.assertRaises(GOSTHMACError) as context:
            test_hmac = gostcrypto.gosthmac.new(None, TEST_KEY)
        self.assertTrue('unsupported mode' in str(context.exception))

    def test_hmac_double_update(self):
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', TEST_KEY)
        test_hmac.update(TEST_DATA)
        test_hmac.update(TEST_DATA)
        self.assertEqual(test_hmac.digest(), TEST_HMAC_256_DOUBLE_UPDATE)

    def test_oid(self):
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_512', TEST_KEY)
        self.assertEqual(test_hmac.oid.__str__(), '1.2.643.7.1.1.4.2')
        self.assertEqual(test_hmac.oid.digit, tuple([1, 2, 643, 7, 1, 1, 4, 2]))
        self.assertEqual(test_hmac.oid.name, 'id-tc26-hmac-gost-3411-12-512')
        self.assertEqual(test_hmac.oid.octet, bytearray([0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x04, 0x02,]))
        test_hmac = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', TEST_KEY)
        self.assertEqual(test_hmac.oid.__str__(), '1.2.643.7.1.1.4.1')
        self.assertEqual(test_hmac.oid.digit, tuple([1, 2, 643, 7, 1, 1, 4, 1]))
        self.assertEqual(test_hmac.oid.name, 'id-tc26-hmac-gost-3411-12-256')
        self.assertEqual(test_hmac.oid.octet, bytearray([0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x04, 0x01,]))
