import unittest
import pytest

import gostcrypto

from gostcrypto.gosthash import GOSTHashError
from gostcrypto.gostoid import ObjectIdentifier

@pytest.mark.hasher
class Test(unittest.TestCase):
    
    TEST_MSG_SHORT = bytearray([
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32
        ])

    TEST_MSG_LONG = u'Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы'.encode('cp1251')

    def test_hash_add_512(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        op_a = self.TEST_MSG_SHORT + b'\x01'
        op_b = test_hasher.block_size * b'\xaf'
        test_result = ('dfe0e1e2e3e4e5e6e7e8dfe0e1e2e3e4e5e6e7e8dfe0e1e2e3e4e5e6e7e8dfe0e1e2e3e4e5e6e7e8dfe0e1e2e3e4e5e6e7e8dfe0e1e2e3e4e5e6e7e8dfe0e1b0')
        result = gostcrypto.gosthash.GOST34112012._hash_add_512(op_a, op_b)
        self.assertEqual(''.join(format(x, '02x') for x in result), test_result)

    def test_hash_get_key(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        test_msg = self.TEST_MSG_SHORT + b'\x01'
        test_result = ('6d897244067f1c66de4deaa188aaf436db4af5cae20e688bd5f8848aa13dcbd54f07aadbc4869a662b70a3082d5701b5fc78715327ec5fc5898136507ff251d2')
        result = test_hasher._hash_get_key(test_msg, 1)
        self.assertEqual(''.join(format(x, '02x') for x in result), test_result)

    def test_hash_e(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        test_msg = self.TEST_MSG_SHORT + b'\x01'
        test_result = ('44c0a9aeea44c9852d4434191482da6c7eabac88b279e82526ec6f61580caca61939f4cbff1d4c9aa8518313d393271009b38fedf1c8690ce3556bbb04e82f49')
        result = test_hasher._hash_e(test_msg, test_msg)
        self.assertEqual(''.join(format(x, '02x') for x in result), test_result)

    def test_hash_g(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        test_msg = self.TEST_MSG_SHORT + b'\x01'
        test_h = test_hasher.block_size * b'\x00'
        test_n = test_hasher.block_size * b'\x00'
        test_result = ('e2da3b6b73e4fe05d9f5b13f793541955c81502c520fedd3c5babb8c90f65427bd8e7333db8a4826a6a95a444166a817384f3921af34ea9111cb2c81f82c10fd')
        result = test_hasher._hash_g(test_h, test_n, test_msg)
        self.assertEqual(''.join(format(x, '02x') for x in result), test_result)

    def test_new(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        _test_hasher = gostcrypto.gosthash.new('streebog256')
        self.assertEqual(test_hasher._name, _test_hasher._name)
        self.assertEqual(test_hasher._buff, _test_hasher._buff)
        self.assertEqual(test_hasher._num_block, _test_hasher._num_block)
        self.assertEqual(test_hasher._pad_block_size, _test_hasher._pad_block_size)
        self.assertEqual(test_hasher._hash_h, _test_hasher._hash_h)
        self.assertEqual(test_hasher._hash_n, _test_hasher._hash_n)
        self.assertEqual(test_hasher._hash_sigma, _test_hasher._hash_sigma)
        test_hasher = gostcrypto.gosthash.new('streebog512', data=self.TEST_MSG_LONG)
        test_result = '1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28'
        result = test_hasher.digest()
        self.assertEqual(''.join(format(x, '02x') for x in result), test_result)

    def test_new_raises(self):
        with self.assertRaises(GOSTHashError) as context:
            test_hasher =  gostcrypto.gosthash.new('test_name')
        self.assertTrue('unsupported hash type' in str(context.exception))

    def test_digest_size(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        self.assertEqual(test_hasher.digest_size, 32)
        test_hasher = gostcrypto.gosthash.new('streebog512')
        self.assertEqual(test_hasher.digest_size, 64)

    def test_block_size(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        self.assertEqual(test_hasher.block_size, 64)
        test_hasher = gostcrypto.gosthash.new('streebog512')
        self.assertEqual(test_hasher.block_size, 64)

    def test_name(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        result = test_hasher.name
        self.assertEqual(result, 'streebog256')

    def test_update(self):
        test_hasher = gostcrypto.gosthash.new('streebog512')
        test_hasher.update(self.TEST_MSG_LONG)
        test_result = 'afc707c4da6c812e85ea2c8e1e225d2e481f7389883b84a76aa4c7f79e77ef987b510c9b45acb727e1f8108f934e91e25d399597cd4cbbe365a4fa1223607fcd'
        self.assertEqual(''.join(format(x, '02x') for x in test_hasher._hash_h), test_result)

    def test_update_raises(self):
        test_hasher =  gostcrypto.gosthash.new('streebog512')
        with self.assertRaises(GOSTHashError) as context:
            test_hasher.update('test_data')
        self.assertTrue('invalid data value' in str(context.exception))

    def test_reset_512(self):
        test_hasher = gostcrypto.gosthash.new('streebog512')
        test_hasher.update(self.TEST_MSG_LONG)
        test_hasher.digest()
        test_hasher.reset()
        self.assertEqual(test_hasher._hash_h, bytearray(test_hasher.block_size))
        self.assertEqual(test_hasher._hash_n, bytearray(test_hasher.block_size))
        self.assertEqual(test_hasher._hash_sigma, bytearray(test_hasher.block_size))
        self.assertEqual(test_hasher._num_block, 0)
        self.assertEqual(test_hasher._pad_block_size, 0)

    def test_reset_256(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        test_hasher.update(self.TEST_MSG_LONG)
        test_hasher.digest()
        test_hasher.reset()
        self.assertEqual(test_hasher._hash_h, test_hasher.block_size * b'\x01')
        self.assertEqual(test_hasher._hash_n, bytearray(test_hasher.block_size))
        self.assertEqual(test_hasher._hash_sigma, bytearray(test_hasher.block_size))
        self.assertEqual(test_hasher._num_block, 0)
        self.assertEqual(test_hasher._pad_block_size, 0)

    def test_digest(self):
        test_hasher = gostcrypto.gosthash.new('streebog512')
        test_hasher.update(self.TEST_MSG_LONG)
        result = test_hasher.digest()
        test_result = '1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28'
        self.assertEqual(''.join(format(x, '02x') for x in result), test_result)

    def test_digest_double_update(self):
        test_hasher = gostcrypto.gosthash.new('streebog512')
        test_hasher.update(u'Се ветри, Стрибожи внуци, веютъ с моря '.encode('cp1251'))
        test_hasher.digest()
        test_hasher.update(u'стрелами на храбрыя плъкы Игоревы'.encode('cp1251'))
        result = test_hasher.digest()
        test_result = '1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28'
        self.assertEqual(''.join(format(x, '02x') for x in result), test_result)

    def test_hexdigest(self):
        test_hasher = gostcrypto.gosthash.new('streebog512')
        test_hasher.update(self.TEST_MSG_LONG)
        result = test_hasher.hexdigest()
        test_result = '1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28'
        self.assertEqual(result, test_result)

    def test_habr_144(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        test_hasher.update(bytearray.fromhex('d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000000100\
                                              000000000000001000002400000001000000feffffff0000000000000000ffffffffffffffffffffffffffffffffffffffff\
                                              ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))
        result = test_hasher.hexdigest()
        test_result = 'c766085540caaa8953bfcf7a1ba220619cee50d65dc242f82f23ba4b180b18e0'
        self.assertEqual(result, test_result)

    def test_oid(self):
        test_hasher = gostcrypto.gosthash.new('streebog256')
        self.assertEqual(test_hasher.oid.__str__(), '1.2.643.7.1.1.2.2')
        self.assertEqual(test_hasher.oid.digit, tuple([1, 2, 643, 7, 1, 1, 2, 2]))
        self.assertEqual(test_hasher.oid.name, 'id-tc26-gost3411-12-256')
        self.assertEqual(test_hasher.oid.octet, bytearray([0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02,]))
        test_hasher = gostcrypto.gosthash.new('streebog512')
        self.assertEqual(test_hasher.oid.__str__(), '1.2.643.7.1.1.2.3')
        self.assertEqual(test_hasher.oid.digit, tuple([1, 2, 643, 7, 1, 1, 2, 3]))
        self.assertEqual(test_hasher.oid.name, 'id-tc26-gost3411-12-512')
        self.assertEqual(test_hasher.oid.octet, bytearray([0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03,]))
        

if __name__ == '__main__':
    unittest.main()

