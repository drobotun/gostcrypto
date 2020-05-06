import unittest
import os
import pytest
from unittest import mock

import gostcrypto
from gostcrypto.utils import bytearray_to_int
from gostcrypto.utils import int_to_bytearray
from gostcrypto.gostsignature import GOSTSignatureError

TEST_CURVE = {
    'id-tc26-gost-3410-2012-256-paramSetTest':dict(
        p=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000000000000000000000000000000000431')),
        a=0x07,
        b=bytearray_to_int(bytearray.fromhex('5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e')),
        m=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3')),
        q=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3')),
        x=0x02,
        y=bytearray_to_int(bytearray.fromhex('08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8'))
    ),
        'id-tc26-gost-3410-2012-256-paramSetTest_raises_1':dict(
        p=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3')),
        a=0x07,
        b=bytearray_to_int(bytearray.fromhex('5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e')),
        m=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3')),
        q=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3')),
        x=0x02,
        y=bytearray_to_int(bytearray.fromhex('08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8'))
    ),
    'id-tc26-gost-3410-2012-256-paramSetTest_raises_2':dict(
        p=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000000000000000000000000000000000431')),
        a=0x07,
        b=bytearray_to_int(bytearray.fromhex('5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e')),
        m=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3')),
        q=0x41,
        x=0x02,
        y=bytearray_to_int(bytearray.fromhex('08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8'))
    ),
    'id-tc26-gost-3410-2012-256-paramSetTest_raises_3':dict(
        p=0x02,
        a=0x07,
        b=bytearray_to_int(bytearray.fromhex('5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e')),
        m=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3')),
        q=0x70,
        x=0x02,
        y=bytearray_to_int(bytearray.fromhex('08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8'))
    ),
    'id-tc26-gost-3410-2012-256-paramSetTest_raises_6':dict(
        p=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000000000000000000000000000000000431')),
        a=0x07,
        b=0x0e,
        m=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3')),
        q=bytearray_to_int(bytearray.fromhex('8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3')),
        x=0x02,
        y=bytearray_to_int(bytearray.fromhex('08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8'))
    ),
    'id-tc26-gost-3410-2012-512-paramSetTest':dict(
        p=bytearray_to_int(bytearray.fromhex('4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15df1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373')),
        a=0x07,
        b=bytearray_to_int(bytearray.fromhex('1cff0806a31116da29d8cfa54e57eb748bc5f377e49400fdd788b649eca1ac4361834013b2ad7322480a89ca58e0cf74bc9e540c2add6897fad0a3084f302adc')),
        m=bytearray_to_int(bytearray.fromhex('4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df')),
        q=bytearray_to_int(bytearray.fromhex('4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df')),
        x=bytearray_to_int(bytearray.fromhex('24d19cc64572ee30f396bf6ebbfd7a6c5213b3b3d7057cc825f91093a68cd762fd60611262cd838dc6b60aa7eee804e28bc849977fac33b4b530f1b120248a9a')),
        y=bytearray_to_int(bytearray.fromhex('2bb312a43bd2ce6e0d020613c857acddcfbf061e91e5f2c3f32447c259f39b2c83ab156d77f1496bf7eb3351e1ee4e43dc1a18b91b24640b6dbb92cb1add371e'))
    ),
    'id-tc26-gost-3410-2012-512-paramSetTest_raises_4':dict(
        p=bytearray_to_int(bytearray.fromhex('4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15df1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373')),
        a=0x07,
        b=bytearray_to_int(bytearray.fromhex('1cff0806a31116da29d8cfa54e57eb748bc5f377e49400fdd788b649eca1ac4361834013b2ad7322480a89ca58e0cf74bc9e540c2add6897fad0a3084f302adc')),
        m=bytearray_to_int(bytearray.fromhex('4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df')),
        q=0x02,
        x=bytearray_to_int(bytearray.fromhex('24d19cc64572ee30f396bf6ebbfd7a6c5213b3b3d7057cc825f91093a68cd762fd60611262cd838dc6b60aa7eee804e28bc849977fac33b4b530f1b120248a9a')),
        y=bytearray_to_int(bytearray.fromhex('2bb312a43bd2ce6e0d020613c857acddcfbf061e91e5f2c3f32447c259f39b2c83ab156d77f1496bf7eb3351e1ee4e43dc1a18b91b24640b6dbb92cb1add371e'))
    ),
    'id-tc26-gost-3410-2012-512-paramSetTest_raises_5':dict(
        p=bytearray_to_int(bytearray.fromhex('4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15df1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373')),
        a=0x07,
        b=bytearray_to_int(bytearray.fromhex('1cff0806a31116da29d8cfa54e57eb748bc5f377e49400fdd788b649eca1ac4361834013b2ad7322480a89ca58e0cf74bc9e540c2add6897fad0a3084f302adc')),
        m=bytearray_to_int(bytearray.fromhex('4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df')),
        q=0x41,
        x=bytearray_to_int(bytearray.fromhex('24d19cc64572ee30f396bf6ebbfd7a6c5213b3b3d7057cc825f91093a68cd762fd60611262cd838dc6b60aa7eee804e28bc849977fac33b4b530f1b120248a9a')),
        y=bytearray_to_int(bytearray.fromhex('2bb312a43bd2ce6e0d020613c857acddcfbf061e91e5f2c3f32447c259f39b2c83ab156d77f1496bf7eb3351e1ee4e43dc1a18b91b24640b6dbb92cb1add371e'))
    ),
    'id-tc26-gost-3410-2012-256-paramSetTestEdvardsA': dict(
        p=bytearray_to_int(bytearray([
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
            0x97
        ])),
        e=0x01,
        d=bytearray_to_int(bytearray([
            0x06, 0x05, 0xf6, 0xb7, 0xc1, 0x83, 0xfa, 0x81,
            0x57, 0x8b, 0xc3, 0x9c, 0xfa, 0xd5, 0x18, 0x13,
            0x2b, 0x9d, 0xf6, 0x28, 0x97, 0x00, 0x9a, 0xf7,
            0xe5, 0x22, 0xc3, 0x2d, 0x6d, 0xc7, 0xbf, 0xfb
        ])),
        m=bytearray_to_int(bytearray([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x3f, 0x63, 0x37, 0x7f, 0x21, 0xed, 0x98,
            0xd7, 0x04, 0x56, 0xbd, 0x55, 0xb0, 0xd8, 0x31,
            0x9c
        ])),
        q=bytearray_to_int(bytearray([
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0f, 0xd8, 0xcd, 0xdf, 0xc8, 0x7b, 0x66, 0x35,
            0xc1, 0x15, 0xaf, 0x55, 0x6c, 0x36, 0x0c, 0x67
        ])),
        u=0x0d,
        v=bytearray_to_int(bytearray([
            0x60, 0xca, 0x1e, 0x32, 0xaa, 0x47, 0x5b, 0x34,
            0x84, 0x88, 0xc3, 0x8f, 0xab, 0x07, 0x64, 0x9c,
            0xe7, 0xef, 0x8d, 0xbe, 0x87, 0xf2, 0x2e, 0x81,
            0xf9, 0x2b, 0x25, 0x92, 0xdb, 0xa3, 0x00, 0xe7
        ])),
    ),
    'id-tc26-gost-3410-2012-256-paramSetTestEdvardsB': dict(
        p=bytearray_to_int(bytearray([
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
            0x97
        ])),
        a=bytearray_to_int(bytearray([
            0x00, 0xc2, 0x17, 0x3f, 0x15, 0x13, 0x98, 0x16,
            0x73, 0xaf, 0x48, 0x92, 0xc2, 0x30, 0x35, 0xa2,
            0x7c, 0xe2, 0x5e, 0x20, 0x13, 0xbf, 0x95, 0xaa,
            0x33, 0xb2, 0x2c, 0x65, 0x6f, 0x27, 0x7e, 0x73,
            0x35
        ])),
        b=bytearray_to_int(bytearray([
            0x29, 0x5f, 0x9b, 0xae, 0x74, 0x28, 0xed, 0x9c,
            0xcc, 0x20, 0xe7, 0xc3, 0x59, 0xa9, 0xd4, 0x1a,
            0x22, 0xfc, 0xcd, 0x91, 0x08, 0xe1, 0x7b, 0xf7,
            0xba, 0x93, 0x37, 0xa6, 0xf8, 0xae, 0x95, 0x13
        ])),
        e=0x01,
        d=bytearray_to_int(bytearray([
            0x06, 0x05, 0xf6, 0xb7, 0xc1, 0x83, 0xfa, 0x81,
            0x57, 0x8b, 0xc3, 0x9c, 0xfa, 0xd5, 0x18, 0x13,
            0x2b, 0x9d, 0xf6, 0x28, 0x97, 0x00, 0x9a, 0xf7,
            0xe5, 0x22, 0xc3, 0x2d, 0x6d, 0xc7, 0xbf, 0xfb
        ])),
        m=bytearray_to_int(bytearray([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x3f, 0x63, 0x37, 0x7f, 0x21, 0xed, 0x98,
            0xd7, 0x04, 0x56, 0xbd, 0x55, 0xb0, 0xd8, 0x31,
            0x9c
        ])),
        q=bytearray_to_int(bytearray([
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0f, 0xd8, 0xcd, 0xdf, 0xc8, 0x7b, 0x66, 0x35,
            0xc1, 0x15, 0xaf, 0x55, 0x6c, 0x36, 0x0c, 0x67
        ])),
        x=bytearray_to_int(bytearray([
            0x00, 0x91, 0xe3, 0x84, 0x43, 0xa5, 0xe8, 0x2c,
            0x0d, 0x88, 0x09, 0x23, 0x42, 0x57, 0x12, 0xb2,
            0xbb, 0x65, 0x8b, 0x91, 0x96, 0x93, 0x2e, 0x02,
            0xc7, 0x8b, 0x25, 0x82, 0xfe, 0x74, 0x2d, 0xaa,
            0x28
        ])),
        y=bytearray_to_int(bytearray([
            0x32, 0x87, 0x94, 0x23, 0xab, 0x1a, 0x03, 0x75,
            0x89, 0x57, 0x86, 0xc4, 0xbb, 0x46, 0xe9, 0x56,
            0x5f, 0xde, 0x0b, 0x53, 0x44, 0x76, 0x67, 0x40,
            0xaf, 0x26, 0x8a, 0xdb, 0x32, 0x32, 0x2e, 0x5c
        ])),
        u=0x0d,
        v=bytearray_to_int(bytearray([
            0x60, 0xca, 0x1e, 0x32, 0xaa, 0x47, 0x5b, 0x34,
            0x84, 0x88, 0xc3, 0x8f, 0xab, 0x07, 0x64, 0x9c,
            0xe7, 0xef, 0x8d, 0xbe, 0x87, 0xf2, 0x2e, 0x81,
            0xf9, 0x2b, 0x25, 0x92, 0xdb, 0xa3, 0x00, 0xe7
        ])),
    )
}
TEST_PRIVATE_KEY_256 = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
TEST_DIGEST_256 = bytearray.fromhex('2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')
TEST_RANDOM_256 = bytearray.fromhex('77105c9b20bcd3122823c8cf6fcc7b956de33814e95b7fe64fed924594dceab3')
TEST_RANDOM_256_EDVARDS = bytearray.fromhex('37105c9b20bcd3122823c8cf6fcc7b956de33814e95b7fe64fed924594dceab3')
TEST_SIGNATURE_256 = bytearray.fromhex('41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc049301456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40')
TEST_SIGNATURE_256_ZERO = bytearray.fromhex('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
TEST_PUBLIC_KEY_256 = bytearray.fromhex('7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da')

TEST_PRIVATE_KEY_512 = bytearray.fromhex('0ba6048aadae241ba40936d47756d7c93091a0e8514669700ee7508e508b102072e8123b2200a0563322dad2827e2714a2636b7bfd18aadfc62967821fa18dd4')
TEST_DIGEST_512 = bytearray.fromhex('3754f3cfacc9e0615c4f4a7c4d8dab531b09b6f9c170c533a71d147035b0c5917184ee536593f4414339976c647c5d5a407adedb1d560c4fc6777d2972075b8c')
TEST_RANDOM_512 = bytearray.fromhex('0359e7f4b1410feacc570456c6801496946312120b39d019d455986e364f365886748ed7a44b3e794434006011842286212273a6d14cf70ea3af71bb1ae679f1')
TEST_SIGNATURE_512 = bytearray.fromhex('2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd35492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae361081b394696ffe8e6585e7a9362d26b6325f56778aadbc081c0bfbe933d52ff5823ce288e8c4f362526080df7f70ce406a6eeb1f56919cb92a9853bde73e5b4a')
TEST_PUBLIC_KEY_512 = bytearray.fromhex('115dc5bc96760c7b48598d8ab9e740d4c4a85a65be33c1815b5c320c854621dd5a515856d13314af69bc5b924c8b4ddff75c45415c1d9dd9dd33612cd530efe137c7c90cd40b0f5621dc3ac1b751cfa0e2634fa0503b3d52639f5d7fb72afd61ea199441d943ffe7f0c70a2759a3cdb84c114e1f9339fdf27f35eca93677beec')

count_urandom = 0

def os_urandom(value):
    add = bytearray([0xff, 0xff])
    global count_urandom
    count_urandom = count_urandom + 1
    if count_urandom == 1:
        return TEST_RANDOM_512 + add
    else:
        return TEST_RANDOM_512

@pytest.mark.signature
class TestMODE256(unittest.TestCase):

    def test_init_raises(self):
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign = gostcrypto.gostsignature.new(None, TEST_CURVE['id-tc26-gost-3410-2012-512-paramSetTest'])
        self.assertTrue('unsupported signature mode' in str(context.exception))

    def test_init_raises_0(self):
        none_curve = dict(f = 0x00, u = 0x00)
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                none_curve)
        self.assertTrue('invalid parameters of the elliptic curve' in str(context.exception))

    def test_init_raises_1(self):
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest_raises_1'])
        self.assertTrue('invalid parameters of the elliptic curve' in str(context.exception))

    def test_init_raises_2(self):
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest_raises_2'])
            TEST_CURVE['id-tc26-gost-3410-2012-512-paramSetTest']['q'] = old_q
        self.assertTrue('invalid parameters of the elliptic curve' in str(context.exception))

    def test_init_raises_3(self):
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest_raises_3'])
        self.assertTrue('invalid parameters of the elliptic curve' in str(context.exception))

    def test_init_raises_4(self):
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
                TEST_CURVE['id-tc26-gost-3410-2012-512-paramSetTest_raises_4'])
        self.assertTrue('invalid parameters of the elliptic curve' in str(context.exception))
        

    def test_init_raises_5(self):
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
                TEST_CURVE['id-tc26-gost-3410-2012-512-paramSetTest_raises_5'])
        self.assertTrue('invalid parameters of the elliptic curve' in str(context.exception))
        

    def test_init_raises_6(self):
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest_raises_6'])
        self.assertTrue('invalid parameters of the elliptic curve' in str(context.exception))

    def test_sign_256(self):
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        self.assertEqual(test_sign.sign(TEST_PRIVATE_KEY_256, TEST_DIGEST_256, TEST_RANDOM_256),
            TEST_SIGNATURE_256)

    def test_sign_edvards_a(self):
        signature = bytearray.fromhex('33dd7cffb7abd971669508fe0d4a1248c3a656108292ed18280cc02d7f0bd3f72e3746c7f6a77491c0edc7b2493f36d007b88c411761c1b303ba851947113166')
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTestEdvardsA'])
        self.assertEqual(test_sign.sign(TEST_PRIVATE_KEY_256, TEST_DIGEST_256, TEST_RANDOM_256_EDVARDS),
            signature)

    def test_sign_edvards_b(self):
        signature = bytearray.fromhex('33dd7cffb7abd971669508fe0d4a1248c3a656108292ed18280cc02d7f0bd3f72e3746c7f6a77491c0edc7b2493f36d007b88c411761c1b303ba851947113166')
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTestEdvardsB'])
        self.assertEqual(test_sign.sign(TEST_PRIVATE_KEY_256, TEST_DIGEST_256, TEST_RANDOM_256_EDVARDS),
            signature)

    def test_sign_raises(self):
        #Test 'invalid private key value'
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        with self.assertRaises(GOSTSignatureError) as context:
            self.assertEqual(test_sign.sign('test_private_key', TEST_DIGEST_256, TEST_RANDOM_256),
                TEST_SIGNATURE_256)
        self.assertTrue('invalid private key value' in str(context.exception))
        #Test 'invalid digest value'
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        with self.assertRaises(GOSTSignatureError) as context:
            self.assertEqual(test_sign.sign(TEST_PRIVATE_KEY_256, 'test_digest', TEST_RANDOM_256),
                TEST_SIGNATURE_256)
        self.assertTrue('invalid digest value' in str(context.exception))
        #Test 'invalid random value' (not a byte object)
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign.sign(TEST_PRIVATE_KEY_256, TEST_DIGEST_256, 'test_random')
        self.assertTrue('invalid random value' in str(context.exception))
        #Test 'invalid random value' (random value >= 'q')
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign.sign(TEST_PRIVATE_KEY_256, TEST_DIGEST_256, TEST_RANDOM_512)
        self.assertTrue('invalid random value' in str(context.exception))

    def test_verify_256(self):
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        self.assertEqual(test_sign.verify(TEST_PUBLIC_KEY_256, TEST_DIGEST_256,
            TEST_SIGNATURE_256), True)
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        self.assertEqual(test_sign.verify(TEST_PUBLIC_KEY_256, TEST_DIGEST_256,
            TEST_SIGNATURE_256_ZERO), False)

    def test_verify_raises(self):
        #Test 'invalid public key value'
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign.verify('test_public_key', TEST_DIGEST_256, TEST_SIGNATURE_256)
        self.assertTrue('invalid public key value' in str(context.exception))
        #Test 'invalid signature value'
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign.verify(TEST_PUBLIC_KEY_256, TEST_DIGEST_256, 'test_signature')
        self.assertTrue('invalid signature value' in str(context.exception))
        #Test 'invalid digest value'
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign.verify(TEST_PUBLIC_KEY_256, 'test_digest', TEST_SIGNATURE_256)
        self.assertTrue('invalid digest value' in str(context.exception))

    def test_public_key_generate_256(self):
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        self.assertEqual(test_sign.public_key_generate(TEST_PRIVATE_KEY_256), TEST_PUBLIC_KEY_256)

    def test_public_key_generate_raises(self):
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        with self.assertRaises(GOSTSignatureError) as context:
            test_sign.public_key_generate('test_private_key')
        self.assertTrue('invalid private key' in str(context.exception))

class TestMODE512(unittest.TestCase):

    def test_sign_512(self):
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
            TEST_CURVE['id-tc26-gost-3410-2012-512-paramSetTest'])
        self.assertEqual(test_sign.sign(TEST_PRIVATE_KEY_512, TEST_DIGEST_512, TEST_RANDOM_512),
            TEST_SIGNATURE_512)

    def test_verify_512(self):
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
            TEST_CURVE['id-tc26-gost-3410-2012-512-paramSetTest'])
        self.assertEqual(test_sign.verify(TEST_PUBLIC_KEY_512, TEST_DIGEST_512,
            TEST_SIGNATURE_512), True)

    def test_public_key_generate_512(self):
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
            TEST_CURVE['id-tc26-gost-3410-2012-512-paramSetTest'])
        self.assertEqual(test_sign.public_key_generate(TEST_PRIVATE_KEY_512), TEST_PUBLIC_KEY_512)

    def test_sign_urandom(self):
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
            TEST_CURVE['id-tc26-gost-3410-2012-512-paramSetTest'])
        with mock.patch('os.urandom', os_urandom):
            test_result = test_sign.sign(TEST_PRIVATE_KEY_512, TEST_DIGEST_512)
        self.assertEqual(test_result, TEST_SIGNATURE_512)

    def test_oid(self):
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
            TEST_CURVE['id-tc26-gost-3410-2012-256-paramSetTest'])
        self.assertEqual(test_sign.oid.__str__(), '1.2.643.7.1.1.1.1')
        self.assertEqual(test_sign.oid.digit, tuple([1, 2, 643, 7, 1, 1, 1, 1]))
        self.assertEqual(test_sign.oid.name, 'id-tc26-gost3410-12-256')
        self.assertEqual(test_sign.oid.octet, bytearray([0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01,]))
        test_sign = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
            TEST_CURVE['id-tc26-gost-3410-2012-512-paramSetTest'])
        self.assertEqual(test_sign.oid.__str__(), '1.2.643.7.1.1.1.2')
        self.assertEqual(test_sign.oid.digit, tuple([1, 2, 643, 7, 1, 1, 1, 2]))
        self.assertEqual(test_sign.oid.name, 'id-tc26-gost3410-12-512')
        self.assertEqual(test_sign.oid.octet, bytearray([0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x02,]))
