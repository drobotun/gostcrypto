import unittest
from unittest import mock
import pytest

import gostcrypto
from  gostcrypto.gostrandom import GOSTRandomError

def os_urandom(value):
    return TEST_SEED

TEST_SEED_ZERO = bytearray([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

TEST_SEED = bytearray([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
])

TEST_RAND = bytearray([
    0xa8, 0xe2, 0xf9, 0x00, 0xdd, 0x4d, 0x7e, 0x24,
    0x5f, 0x09, 0x75, 0x3d, 0x01, 0xe8, 0x75, 0xfc,
    0x38, 0xf1, 0x4f, 0xf5, 0x25, 0x4c, 0x94, 0xea,
    0xdb, 0x45, 0x1e, 0x4a, 0xb6, 0x03, 0xb1, 0x47,
])

TEST_RAND_LONG = bytearray([
    0x66, 0xc5, 0xb4, 0xf0, 0x4f, 0xfa, 0xc3, 0x59,
    0xd6, 0x50, 0xd0, 0xff, 0x6c, 0xa8, 0x88, 0x73,
    0x69, 0x79, 0x79, 0xeb, 0x9c, 0xc6, 0xc6, 0x3d,
    0x3e, 0xab, 0x26, 0x62, 0xf7, 0xd4, 0x68, 0x75,
    0xa8, 0xe2, 0xf9, 0x00, 0xdd, 0x4d, 0x7e, 0x24,
    0x5f, 0x09, 0x75, 0x3d, 0x01, 0xe8, 0x75, 0xfc,
    0x38, 0xf1, 0x4f, 0xf5, 0x25, 0x4c, 0x94, 0xea,
    0xdb, 0x45, 0x1e, 0x4a, 0xb6, 0x03, 0xb1, 0x47,
    0x4a, 0xfe, 0x17, 0x61,
])

class Test(unittest.TestCase):

    def test_new_raises(self):
        with self.assertRaises(GOSTRandomError) as context:
            test_random = gostcrypto.gostrandom.new(32, rand_k='test_seed', size_s=gostcrypto.gostrandom.SIZE_S_256)
        self.assertTrue('invalid seed value' in str(context.exception))

    def test_random(self):
        test_random = gostcrypto.gostrandom.new(32, rand_k=TEST_SEED, size_s=gostcrypto.gostrandom.SIZE_S_256)
        self.assertEqual(test_random.random(), TEST_RAND)
        test_random = gostcrypto.gostrandom.new(68, rand_k=TEST_SEED, size_s=gostcrypto.gostrandom.SIZE_S_256)
        self.assertEqual(test_random.random(), TEST_RAND_LONG)

    def test_random_raises(self):
        test_random = gostcrypto.gostrandom.new(32, rand_k=TEST_SEED_ZERO, size_s=gostcrypto.gostrandom.SIZE_S_256)
        with self.assertRaises(GOSTRandomError) as context:
            test_random.random()
        self.assertTrue('the seed value is zero' in str(context.exception))
        test_random = gostcrypto.gostrandom.new(32, rand_k=TEST_SEED, size_s=gostcrypto.gostrandom.SIZE_S_256)
        test_random._limit = 0
        with self.assertRaises(GOSTRandomError) as context:
            test_random.random()
        self.assertTrue('exceeded the limit value of the counter' in str(context.exception))
        test_random = gostcrypto.gostrandom.new(68, rand_k=TEST_SEED, size_s=gostcrypto.gostrandom.SIZE_S_256)
        test_random._limit = 0
        with self.assertRaises(GOSTRandomError) as context:
            test_random.random()
        self.assertTrue('exceeded the limit value of the counter' in str(context.exception))

    def test_reset(self):
        test_random = gostcrypto.gostrandom.new(32, rand_k=TEST_SEED_ZERO, size_s=gostcrypto.gostrandom.SIZE_S_256)
        test_random.reset(TEST_SEED)
        self.assertEqual(test_random.random(), TEST_RAND)

    def test_reset_raises(self):
        test_random = gostcrypto.gostrandom.new(32, rand_k=TEST_SEED_ZERO, size_s=gostcrypto.gostrandom.SIZE_S_256)
        with self.assertRaises(GOSTRandomError) as context:
            test_random.reset('test_seed')
        self.assertTrue('invalid seed value' in str(context.exception))

    def test_new_urandom(self):
        with mock.patch('os.urandom', os_urandom):
            test_random = gostcrypto.gostrandom.new(32, rand_k=b'', size_s=gostcrypto.gostrandom.SIZE_S_256)
        self.assertEqual(test_random.random(), TEST_RAND)

    def test_reset_urandom(self):
        test_random = gostcrypto.gostrandom.new(32, rand_k=TEST_SEED_ZERO, size_s=gostcrypto.gostrandom.SIZE_S_256)
        with mock.patch('os.urandom', os_urandom):
            test_random.reset()
        self.assertEqual(test_random.random(), TEST_RAND)
