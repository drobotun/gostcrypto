import unittest
import pytest

import gostcrypto
from gostcrypto.gostcipher import GOSTCipherError

@pytest.mark.cipher
class TestKuznechik(unittest.TestCase):

    TEST_KEY = bytearray([
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ])

    ENCRYPT_TEST_STRING = bytearray([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    ])

    DECRYPT_TEST_STRING = bytearray([
        0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
    ])

    def test_s(self):
        test_data_1 = bytearray([
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        ])
        test_data_2 = bytearray([
            0xb6, 0x6c, 0xd8, 0x88, 0x7d, 0x38, 0xe8, 0xd7, 0x77, 0x65, 0xae, 0xea, 0x0c, 0x9a, 0x7e, 0xfc,
        ])
        test_data_3 = bytearray([
            0x55, 0x9d, 0x8d, 0xd7, 0xbd, 0x06, 0xcb, 0xfe, 0x7e, 0x7b, 0x26, 0x25, 0x23, 0x28, 0x0d, 0x39,
        ])
        test_data_4 = bytearray([
            0x0c, 0x33, 0x22, 0xfe, 0xd5, 0x31, 0xe4, 0x63, 0x0d, 0x80, 0xef, 0x5c, 0x5a, 0x81, 0xc5, 0x0b,
        ])
        test_data_5 = bytearray([
            0x23, 0xae, 0x65, 0x63, 0x3f, 0x84, 0x2d, 0x29, 0xc5, 0xdf, 0x52, 0x9c, 0x13, 0xf5, 0xac, 0xda,
        ])
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_s(test_data_1), test_data_2)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_s(test_data_2), test_data_3)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_s(test_data_3), test_data_4)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_s(test_data_4), test_data_5)

    def test_s_reverse(self):
        test_data_1 = bytearray([
            0x23, 0xae, 0x65, 0x63, 0x3f, 0x84, 0x2d, 0x29, 0xc5, 0xdf, 0x52, 0x9c, 0x13, 0xf5, 0xac, 0xda,
        ])
        test_data_2 = bytearray([
            0x0c, 0x33, 0x22, 0xfe, 0xd5, 0x31, 0xe4, 0x63, 0x0d, 0x80, 0xef, 0x5c, 0x5a, 0x81, 0xc5, 0x0b,
        ])
        test_data_3 = bytearray([
            0x55, 0x9d, 0x8d, 0xd7, 0xbd, 0x06, 0xcb, 0xfe, 0x7e, 0x7b, 0x26, 0x25, 0x23, 0x28, 0x0d, 0x39,
        ])
        test_data_4 = bytearray([
            0xb6, 0x6c, 0xd8, 0x88, 0x7d, 0x38, 0xe8, 0xd7, 0x77, 0x65, 0xae, 0xea, 0x0c, 0x9a, 0x7e, 0xfc,
        ])
        test_data_5 = bytearray([
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        ])
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_s_reverse(test_data_1), test_data_2)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_s_reverse(test_data_2), test_data_3)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_s_reverse(test_data_3), test_data_4)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_s_reverse(test_data_4), test_data_5)

    def test_r(self):
        test_data_1 = bytearray([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        ])
        test_data_2 = bytearray([
            0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ])
        test_data_3 = bytearray([
            0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        test_data_4 = bytearray([
            0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        test_data_5 = bytearray([
            0x0d, 0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_r(test_data_1), test_data_2)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_r(test_data_2), test_data_3)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_r(test_data_3), test_data_4)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_r(test_data_4), test_data_5)

    def test_r_reverse(self):
        test_data_1 = bytearray([
            0x0d, 0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        test_data_2 = bytearray([
            0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        test_data_3 = bytearray([
            0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        test_data_4 = bytearray([
            0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ])
        test_data_5 = bytearray([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        ])
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_r_reverse(test_data_1), test_data_2)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_r_reverse(test_data_2), test_data_3)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_r_reverse(test_data_3), test_data_4)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_r_reverse(test_data_4), test_data_5)

    def test_l(self):
        test_data_1 = bytearray([
            0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        test_data_2 = bytearray([
            0xd4, 0x56, 0x58, 0x4d, 0xd0, 0xe3, 0xe8, 0x4c, 0xc3, 0x16, 0x6e, 0x4b, 0x7f, 0xa2, 0x89, 0x0d,
        ])
        test_data_3 = bytearray([
            0x79, 0xd2, 0x62, 0x21, 0xb8, 0x7b, 0x58, 0x4c, 0xd4, 0x2f, 0xbc, 0x4f, 0xfe, 0xa5, 0xde, 0x9a,
        ])
        test_data_4 = bytearray([
            0x0e, 0x93, 0x69, 0x1a, 0x0c, 0xfc, 0x60, 0x40, 0x8b, 0x7b, 0x68, 0xf6, 0x6b, 0x51, 0x3c, 0x13,
        ])
        test_data_5 = bytearray([
            0xe6, 0xa8, 0x09, 0x4f, 0xee, 0x0a, 0xa2, 0x04, 0xfd, 0x97, 0xbc, 0xb0, 0xb4, 0x4b, 0x85, 0x80,
        ])
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_l(test_data_1), test_data_2)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_l(test_data_2), test_data_3)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_l(test_data_3), test_data_4)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_l(test_data_4), test_data_5)

    def test_l_reverse(self):
        test_data_1 = bytearray([
            0xe6, 0xa8, 0x09, 0x4f, 0xee, 0x0a, 0xa2, 0x04, 0xfd, 0x97, 0xbc, 0xb0, 0xb4, 0x4b, 0x85, 0x80,
        ])
        test_data_2 = bytearray([
            0x0e, 0x93, 0x69, 0x1a, 0x0c, 0xfc, 0x60, 0x40, 0x8b, 0x7b, 0x68, 0xf6, 0x6b, 0x51, 0x3c, 0x13,
        ])
        test_data_3 = bytearray([
            0x79, 0xd2, 0x62, 0x21, 0xb8, 0x7b, 0x58, 0x4c, 0xd4, 0x2f, 0xbc, 0x4f, 0xfe, 0xa5, 0xde, 0x9a,
        ])
        test_data_4 = bytearray([
            0xd4, 0x56, 0x58, 0x4d, 0xd0, 0xe3, 0xe8, 0x4c, 0xc3, 0x16, 0x6e, 0x4b, 0x7f, 0xa2, 0x89, 0x0d,
        ])
        test_data_5 = bytearray([
            0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_l_reverse(test_data_1), test_data_2)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_l_reverse(test_data_2), test_data_3)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_l_reverse(test_data_3), test_data_4)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Kuznechik._cipher_l_reverse(test_data_4), test_data_5)

    def test_expand_key(self):
        test_iter_key = [bytearray([
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            ]), bytearray([
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            ]), bytearray([
            0xdb, 0x31, 0x48, 0x53, 0x15, 0x69, 0x43, 0x43, 0x22, 0x8d, 0x6a, 0xef, 0x8c, 0xc7, 0x8c, 0x44,
            ]), bytearray([
            0x3d, 0x45, 0x53, 0xd8, 0xe9, 0xcf, 0xec, 0x68, 0x15, 0xeb, 0xad, 0xc4, 0x0a, 0x9f, 0xfd, 0x04,
            ]), bytearray([
            0x57, 0x64, 0x64, 0x68, 0xc4, 0x4a, 0x5e, 0x28, 0xd3, 0xe5, 0x92, 0x46, 0xf4, 0x29, 0xf1, 0xac,
            ]), bytearray([
            0xbd, 0x07, 0x94, 0x35, 0x16, 0x5c, 0x64, 0x32, 0xb5, 0x32, 0xe8, 0x28, 0x34, 0xda, 0x58, 0x1b,
            ]), bytearray([
            0x51, 0xe6, 0x40, 0x75, 0x7e, 0x87, 0x45, 0xde, 0x70, 0x57, 0x27, 0x26, 0x5a, 0x00, 0x98, 0xb1,
            ]), bytearray([
            0x5a, 0x79, 0x25, 0x01, 0x7b, 0x9f, 0xdd, 0x3e, 0xd7, 0x2a, 0x91, 0xa2, 0x22, 0x86, 0xf9, 0x84,
            ]), bytearray([
            0xbb, 0x44, 0xe2, 0x53, 0x78, 0xc7, 0x31, 0x23, 0xa5, 0xf3, 0x2f, 0x73, 0xcd, 0xb6, 0xe5, 0x17,
            ]), bytearray([
            0x72, 0xe9, 0xdd, 0x74, 0x16, 0xbc, 0xf4, 0x5b, 0x75, 0x5d, 0xba, 0xa8, 0x8e, 0x4a, 0x40, 0x43,
            ])
        ]
        test_cipher = gostcrypto.gostcipher.GOST34122015Kuznechik(self.TEST_KEY)
        self.assertEqual(test_cipher._cipher_iter_key[0], test_iter_key[0])
        self.assertEqual(test_cipher._cipher_iter_key[1], test_iter_key[1])
        self.assertEqual(test_cipher._cipher_iter_key[2], test_iter_key[2])
        self.assertEqual(test_cipher._cipher_iter_key[3], test_iter_key[3])
        self.assertEqual(test_cipher._cipher_iter_key[4], test_iter_key[4])
        self.assertEqual(test_cipher._cipher_iter_key[5], test_iter_key[5])
        self.assertEqual(test_cipher._cipher_iter_key[6], test_iter_key[6])
        self.assertEqual(test_cipher._cipher_iter_key[7], test_iter_key[7])
        self.assertEqual(test_cipher._cipher_iter_key[8], test_iter_key[8])
        self.assertEqual(test_cipher._cipher_iter_key[9], test_iter_key[9])

    def test_decrypt(self):
        test_cipher = gostcrypto.gostcipher.GOST34122015Kuznechik(self.TEST_KEY)
        self.assertEqual(test_cipher.decrypt(self.DECRYPT_TEST_STRING), self.ENCRYPT_TEST_STRING)

    def test_encrypt(self):
        test_cipher = gostcrypto.gostcipher.GOST34122015Kuznechik(self.TEST_KEY)
        self.assertEqual(test_cipher.encrypt(self.ENCRYPT_TEST_STRING), self.DECRYPT_TEST_STRING)

    def test_key_size(self):
        test_cipher = gostcrypto.gostcipher.GOST34122015Kuznechik(self.TEST_KEY)
        self.assertEqual(test_cipher.key_size, 32)

@pytest.mark.cipher
class TestMagma(unittest.TestCase):

    TEST_KEY = bytearray([
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    ])

    ENCRYPT_TEST_STRING = bytearray([
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ])

    DECRYPT_TEST_STRING = bytearray([
        0x4e, 0xe9, 0x01, 0xe5, 0xc2, 0xd8, 0xca, 0x3d,
    ])

    def test_t(self):
        test_data_1 = bytearray([
            0xfd, 0xb9, 0x75, 0x31,
        ])
        test_data_2 = bytearray([
            0x2a, 0x19, 0x6f, 0x34,
        ])
        test_data_3 = bytearray([
            0xeb, 0xd9, 0xf0, 0x3a,
        ])
        test_data_4 = bytearray([
            0xb0, 0x39, 0xbb, 0x3d,
        ])
        test_data_5 = bytearray([
            0x68, 0x69, 0x54, 0x33,
        ])
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Magma._cipher_t(test_data_1), test_data_2)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Magma._cipher_t(test_data_2), test_data_3)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Magma._cipher_t(test_data_3), test_data_4)
        self.assertEqual(gostcrypto.gostcipher.GOST34122015Magma._cipher_t(test_data_4), test_data_5)

    def test_encrypt(self):
        test_cipher = gostcrypto.gostcipher.GOST34122015Magma(self.TEST_KEY)
        self.assertEqual(test_cipher.encrypt(self.ENCRYPT_TEST_STRING), self.DECRYPT_TEST_STRING)

    def test_decrypt(self):
        test_cipher = gostcrypto.gostcipher.GOST34122015Magma(self.TEST_KEY)
        self.assertEqual(test_cipher.decrypt(self.DECRYPT_TEST_STRING), self.ENCRYPT_TEST_STRING)

    def test_key_size(self):
        test_cipher = gostcrypto.gostcipher.GOST34122015Magma(self.TEST_KEY)
        self.assertEqual(test_cipher.key_size, 32)

@pytest.mark.cipher
class TestGOST34132015Kuznechik(unittest.TestCase):

    TEST_KEY = bytearray([
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ])

    TEST_PLAIN_TEXT = bytearray([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11,
    ])

    TEST_INIT_VECT = bytearray([
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    ])

    TEST_INIT_VECT_CTR = bytearray([
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0,
    ])

    TEST_CIPHER_TEXT_ECB = bytearray([
        0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
        0xb4, 0x29, 0x91, 0x2c, 0x6e, 0x00, 0x32, 0xf9, 0x28, 0x54, 0x52, 0xd7, 0x67, 0x18, 0xd0, 0x8b,
        0xf0, 0xca, 0x33, 0x54, 0x9d, 0x24, 0x7c, 0xee, 0xf3, 0xf5, 0xa5, 0x31, 0x3b, 0xd4, 0xb1, 0x57,
        0xd0, 0xb0, 0x9c, 0xcd, 0xe8, 0x30, 0xb9, 0xeb, 0x3a, 0x02, 0xc4, 0xc5, 0xaa, 0x8a, 0xda, 0x98,
    ])

    TEST_CIPHER_TEXT_CBC = bytearray([
        0x68, 0x99, 0x72, 0xd4, 0xa0, 0x85, 0xfa, 0x4d, 0x90, 0xe5, 0x2e, 0x3d, 0x6d, 0x7d, 0xcc, 0x27,
        0x28, 0x26, 0xe6, 0x61, 0xb4, 0x78, 0xec, 0xa6, 0xaf, 0x1e, 0x8e, 0x44, 0x8d, 0x5e, 0xa5, 0xac,
        0xfe, 0x7b, 0xab, 0xf1, 0xe9, 0x19, 0x99, 0xe8, 0x56, 0x40, 0xe8, 0xb0, 0xf4, 0x9d, 0x90, 0xd0,
        0x16, 0x76, 0x88, 0x06, 0x5a, 0x89, 0x5c, 0x63, 0x1a, 0x2d, 0x9a, 0x15, 0x60, 0xb6, 0x39, 0x70,
    ])

    TEST_CIPHER_TEXT_CFB = bytearray([
        0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
        0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
        0x79, 0xf2, 0xa8, 0xeb, 0x5c, 0xc6, 0x8d, 0x38, 0x84, 0x2d, 0x26, 0x4e, 0x97, 0xa2, 0x38, 0xb5,
        0x4f, 0xfe, 0xbe, 0xcd, 0x4e, 0x92, 0x2d, 0xe6, 0xc7, 0x5b, 0xd9, 0xdd, 0x44, 0xfb, 0xf4, 0xd1,
    ])

    TEST_CIPHER_TEXT_OFB = bytearray([
        0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
        0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
        0x66, 0xa2, 0x57, 0xac, 0x3c, 0xa0, 0xb8, 0xb1, 0xc8, 0x0f, 0xe7, 0xfc, 0x10, 0x28, 0x8a, 0x13,
        0x20, 0x3e, 0xbb, 0xc0, 0x66, 0x13, 0x86, 0x60, 0xa0, 0x29, 0x22, 0x43, 0xf6, 0x90, 0x31, 0x50,
    ])

    TEST_CIPHER_TEXT_CTR = bytearray([
        0xf1, 0x95, 0xd8, 0xbe, 0xc1, 0x0e, 0xd1, 0xdb, 0xd5, 0x7b, 0x5f, 0xa2, 0x40, 0xbd, 0xa1, 0xb8,
        0x85, 0xee, 0xe7, 0x33, 0xf6, 0xa1, 0x3e, 0x5d, 0xf3, 0x3c, 0xe4, 0xb3, 0x3c, 0x45, 0xde, 0xe4,
        0xa5, 0xea, 0xe8, 0x8b, 0xe6, 0x35, 0x6e, 0xd3, 0xd5, 0xe8, 0x77, 0xf1, 0x35, 0x64, 0xa3, 0xa5,
        0xcb, 0x91, 0xfa, 0xb1, 0xf2, 0x0c, 0xba, 0xb6, 0xd1, 0xc6, 0xd1, 0x58, 0x20, 0xbd, 0xba, 0x73,
    ])

    TEST_PLAIN_TEXT_NO_MUL = bytearray([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff,
    ])

    TEST_PLAIN_TEXT_PAD_1 = bytearray([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x00, 0x00, 0x00,
    ])

    TEST_PLAIN_TEXT_PAD_2 = bytearray([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    TEST_PLAIN_TEXT_SHORT = bytearray([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa,
    ])

    TEST_CIPHER_TEXT_ECB_SHORT = bytearray([
        0x3c, 0xc3, 0x42, 0xdf, 0xcd, 0x5a, 0x7b, 0xef, 0x4e, 0x80, 0x1c, 0xa9, 0x6d, 0x84, 0x6f, 0xe6,
    ])

    TEST_PLAIN_TEXT_SHORT_PAD_1 = bytearray([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x00, 0x00,
    ])

    TEST_CIPHER_TEXT_ECB_PAD_1 = bytearray([
        0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
        0xb4, 0x29, 0x91, 0x2c, 0x6e, 0x00, 0x32, 0xf9, 0x28, 0x54, 0x52, 0xd7, 0x67, 0x18, 0xd0, 0x8b,
        0xf0, 0xca, 0x33, 0x54, 0x9d, 0x24, 0x7c, 0xee, 0xf3, 0xf5, 0xa5, 0x31, 0x3b, 0xd4, 0xb1, 0x57,
        0xd8, 0x8c, 0xdb, 0x75, 0x60, 0x99, 0xf9, 0xd8, 0xd6, 0x57, 0x89, 0xb2, 0xce, 0x51, 0x42, 0x5c,
    ])

    TEST_CIPHER_TEXT_ECB_PAD_2 = bytearray([
        0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
        0xb4, 0x29, 0x91, 0x2c, 0x6e, 0x00, 0x32, 0xf9, 0x28, 0x54, 0x52, 0xd7, 0x67, 0x18, 0xd0, 0x8b,
        0xf0, 0xca, 0x33, 0x54, 0x9d, 0x24, 0x7c, 0xee, 0xf3, 0xf5, 0xa5, 0x31, 0x3b, 0xd4, 0xb1, 0x57,
        0xe2, 0xb7, 0x75, 0x12, 0x7f, 0x93, 0x2e, 0xce, 0x26, 0x2a, 0x60, 0x25, 0xc0, 0x63, 0xdb, 0xcb,
        0x94, 0xbe, 0xc1, 0x5e, 0x26, 0x9c, 0xf1, 0xe5, 0x06, 0xf0, 0x2b, 0x99, 0x4c, 0x0a, 0x8e, 0xa0

    ])

    TEST_CIPHER_TEXT_CTR_NO_MUL = bytearray([
        0xf1, 0x95, 0xd8, 0xbe, 0xc1, 0x0e, 0xd1, 0xdb, 0xd5, 0x7b, 0x5f, 0xa2, 0x40, 0xbd, 0xa1, 0xb8,
        0x85, 0xee, 0xe7, 0x33, 0xf6, 0xa1, 0x3e, 0x5d, 0xf3, 0x3c, 0xe4, 0xb3, 0x3c, 0x45, 0xde, 0xe4,
        0xa5, 0xea, 0xe8, 0x8b, 0xe6, 0x35, 0x6e, 0xd3, 0xd5, 0xe8, 0x77, 0xf1, 0x35, 0x64, 0xa3, 0xa5,
        0xcb, 0x91, 0xfa, 0xb1, 0xf2, 0x0c, 0xba, 0xb6, 0xd1, 0xc6, 0xd1, 0x58, 0x20,
    ])

    TEST_CIPHER_TEXT_CBC_PAD_1 = bytearray([
        0x68, 0x99, 0x72, 0xd4, 0xa0, 0x85, 0xfa, 0x4d, 0x90, 0xe5, 0x2e, 0x3d, 0x6d, 0x7d, 0xcc, 0x27,
        0x28, 0x26, 0xe6, 0x61, 0xb4, 0x78, 0xec, 0xa6, 0xaf, 0x1e, 0x8e, 0x44, 0x8d, 0x5e, 0xa5, 0xac,
        0xfe, 0x7b, 0xab, 0xf1, 0xe9, 0x19, 0x99, 0xe8, 0x56, 0x40, 0xe8, 0xb0, 0xf4, 0x9d, 0x90, 0xd0,
        0xe2, 0x8b, 0xb9, 0x02, 0x9c, 0x31, 0xaa, 0x5f, 0xe5, 0x56, 0x11, 0x92, 0xeb, 0x9c, 0x3f, 0x70,
    ])

    TEST_CIPHER_TEXT_CBC_PAD_2 = bytearray([
        0x68, 0x99, 0x72, 0xd4, 0xa0, 0x85, 0xfa, 0x4d, 0x90, 0xe5, 0x2e, 0x3d, 0x6d, 0x7d, 0xcc, 0x27,
        0x28, 0x26, 0xe6, 0x61, 0xb4, 0x78, 0xec, 0xa6, 0xaf, 0x1e, 0x8e, 0x44, 0x8d, 0x5e, 0xa5, 0xac,
        0xfe, 0x7b, 0xab, 0xf1, 0xe9, 0x19, 0x99, 0xe8, 0x56, 0x40, 0xe8, 0xb0, 0xf4, 0x9d, 0x90, 0xd0,
        0x26, 0x12, 0x5a, 0x8d, 0xde, 0x53, 0x5f, 0x61, 0x47, 0xdb, 0xde, 0xba, 0xd2, 0x83, 0x24, 0xbe,
        0x82, 0x8e, 0xa5, 0xda, 0xf2, 0x9f, 0x23, 0x9f, 0x47, 0x32, 0xcd, 0x08, 0xbd, 0xf6, 0xab, 0x18,
    ])

    TEST_CIPHER_TEXT_OFB_NO_MUL = bytearray([
        0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
        0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
        0x66, 0xa2, 0x57, 0xac, 0x3c, 0xa0, 0xb8, 0xb1, 0xc8, 0x0f, 0xe7, 0xfc, 0x10, 0x28, 0x8a, 0x13,
        0x20, 0x3e, 0xbb, 0xc0, 0x66, 0x13, 0x86, 0x60, 0xa0, 0x29, 0x22, 0x43, 0xf6,
    ])

    TEST_CIPHER_TEXT_CFB_NO_MUL = bytearray([
        0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
        0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
        0x79, 0xf2, 0xa8, 0xeb, 0x5c, 0xc6, 0x8d, 0x38, 0x84, 0x2d, 0x26, 0x4e, 0x97, 0xa2, 0x38, 0xb5,
        0x4f, 0xfe, 0xbe, 0xcd, 0x4e, 0x92, 0x2d, 0xe6, 0xc7, 0x5b, 0xd9, 0xdd, 0x44,
    ])

    

    TEST_MAC_VALUE = bytearray([
        0x33, 0x6f, 0x4d, 0x29, 0x60, 0x59, 0xfb, 0xe3, 0x4d, 0xde, 0xb3, 0x5b, 0x37, 0x74, 0x9c, 0x67,
    ])

    TEST_MAC_VALUE_DOUBLE = bytearray([
        0x83, 0xd2, 0x11, 0x9c, 0x63, 0xa3, 0x7f, 0x8e, 0x85, 0x62, 0x4d, 0x90, 0x0a, 0x25, 0x94, 0xb4,
    ])

    TEST_MAC_VALUE_PAD = bytearray([
        0x1f, 0x03, 0x17, 0x90, 0xa8, 0x32, 0x7e, 0x74, 0xc8, 0x34, 0x1e, 0xed, 0x4c, 0xda, 0x48, 0xbd,
    ])

    TEST_MAC_VALUE_DOUBLE_PAD = bytearray([
        0x7d, 0x03, 0x47, 0xe5, 0x4b, 0x8f, 0x6b, 0xfa, 0xc9, 0x3f, 0x73, 0x5c, 0x0d, 0x72, 0xc2, 0x3b,
    ])

    def test_new_raises(self):
        with self.assertRaises(GOSTCipherError) as context:
            test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, 'test_mode')
        self.assertTrue('unsupported cipher mode' in str(context.exception))
        with self.assertRaises(GOSTCipherError) as context:
            test_obj =  gostcrypto.gostcipher.new('test_algorithm', self.TEST_KEY,
                gostcrypto.gostcipher.MODE_ECB)
        self.assertTrue('unsupported cipher algorithm' in str(context.exception))
        with self.assertRaises(GOSTCipherError) as context:
            test_obj =  gostcrypto.gostcipher.new('kuznechik', 'test_key',
                gostcrypto.gostcipher.MODE_ECB)
        self.assertTrue('invalid key value' in str(context.exception))
        with self.assertRaises(GOSTCipherError) as context:
            test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY,
                gostcrypto.gostcipher.MODE_CBC, init_vect='test_init_vect')
        self.assertTrue('invalid initialization vector value' in str(context.exception))
        with self.assertRaises(GOSTCipherError) as context:
            test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY,
                gostcrypto.gostcipher.MODE_CFB, init_vect='test_init_vect')
        self.assertTrue('invalid initialization vector value' in str(context.exception))
        with self.assertRaises(GOSTCipherError) as context:
            test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY,
                gostcrypto.gostcipher.MODE_OFB, init_vect='test_init_vect')
        self.assertTrue('invalid initialization vector value' in str(context.exception))
        with self.assertRaises(GOSTCipherError) as context:
            test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY,
                gostcrypto.gostcipher.MODE_CTR, init_vect='test_init_vect')
        self.assertTrue('invalid initialization vector value' in str(context.exception))
        with self.assertRaises(GOSTCipherError) as context:
            test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY,
                gostcrypto.gostcipher.MODE_ECB, pad_mode='test_pad')
        self.assertTrue('invalid padding mode' in str(context.exception))
        with self.assertRaises(GOSTCipherError) as context:
            test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY,
                gostcrypto.gostcipher.MODE_CBC, init_vect = self.TEST_INIT_VECT,
                pad_mode='test_pad')
        self.assertTrue('invalid padding mode' in str(context.exception))

    def test_ecb_encrypt(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_ECB)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_ECB_PAD_1)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB,
            pad_mode=gostcrypto.gostcipher.PAD_MODE_2)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_ECB_PAD_2)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_SHORT), self.TEST_CIPHER_TEXT_ECB_SHORT)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.encrypt('test_plaintext')
        self.assertTrue('invalid plaintext data' in str(context.exception))

    def test_ecb_decrypt(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_ECB), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_ECB_PAD_1), self.TEST_PLAIN_TEXT_PAD_1)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB,
            pad_mode=gostcrypto.gostcipher.PAD_MODE_2)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_ECB_PAD_2), self.TEST_PLAIN_TEXT_PAD_2)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_ECB_SHORT), self.TEST_PLAIN_TEXT_SHORT_PAD_1)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.decrypt('test_ciphertext')
        self.assertTrue('invalid ciphertext data' in str(context.exception))

    def test_ctr_encrypt(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CTR)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CTR_NO_MUL)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.encrypt('test_plaintext')
        self.assertTrue('invalid plaintext data' in str(context.exception))

    def test_ctr_encrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CTR)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CTR_NO_MUL)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.encrypt('test_plaintext')
        self.assertTrue('invalid plaintext data' in str(context.exception))

    def test_ctr_decrypt(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CTR), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CTR_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.decrypt('test_ciphertext')
        self.assertTrue('invalid ciphertext data' in str(context.exception))

    def test_ctr_decrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CTR), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CTR_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.decrypt('test_ciphertext')
        self.assertTrue('invalid ciphertext data' in str(context.exception))
    
    def test_cbc_encrypt(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CBC)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CBC_PAD_1)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT, pad_mode=gostcrypto.gostcipher.PAD_MODE_2)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CBC_PAD_2)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.encrypt('test_plaintext')
        self.assertTrue('invalid plaintext data' in str(context.exception))

    def test_cbc_encrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CBC)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CBC_PAD_1)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            pad_mode=gostcrypto.gostcipher.PAD_MODE_2)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CBC_PAD_2)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.encrypt('test_plaintext')
        self.assertTrue('invalid plaintext data' in str(context.exception))

    def test_cbc_decrypt(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CBC), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CBC_PAD_1), self.TEST_PLAIN_TEXT_PAD_1)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT, pad_mode=gostcrypto.gostcipher.PAD_MODE_2)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CBC_PAD_2), self.TEST_PLAIN_TEXT_PAD_2)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.decrypt('test_ciphertext')
        self.assertTrue('invalid ciphertext data' in str(context.exception))

    def test_cbc_decrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CBC), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CBC_PAD_1), self.TEST_PLAIN_TEXT_PAD_1)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            pad_mode=gostcrypto.gostcipher.PAD_MODE_2)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CBC_PAD_2), self.TEST_PLAIN_TEXT_PAD_2)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.decrypt('test_ciphertext')
        self.assertTrue('invalid ciphertext data' in str(context.exception))

    def test_cfb_encrypt(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CFB)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CFB_NO_MUL)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.encrypt('test_plaintext')
        self.assertTrue('invalid plaintext data' in str(context.exception))

    def test_cfb_encrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CFB)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CFB_NO_MUL)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.encrypt('test_plaintext')
        self.assertTrue('invalid plaintext data' in str(context.exception))

    def test_cfb_decrypt(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CFB), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CFB_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.decrypt('test_ciphertext')
        self.assertTrue('invalid ciphertext data' in str(context.exception))

    def test_cfb_decrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CFB), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CFB_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)
        test_obj =  gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.decrypt('test_ciphertext')
        self.assertTrue('invalid ciphertext data' in str(context.exception))

    def test_ofb_encrypt(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_OFB)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_OFB_NO_MUL)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.encrypt('test_plaintext')
        self.assertTrue('invalid plaintext data' in str(context.exception))

    def test_ofb_encrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_OFB)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_OFB_NO_MUL)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.encrypt('test_plaintext')
        self.assertTrue('invalid plaintext data' in str(context.exception))

    def test_ofb_decrypt(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_OFB), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_OFB_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.decrypt('test_ciphertext')
        self.assertTrue('invalid ciphertext data' in str(context.exception))

    def test_ofb_decrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_OFB), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_OFB_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.decrypt('test_ciphertext')
        self.assertTrue('invalid ciphertext data' in str(context.exception))

    def test_mac_calculate(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC)
        test_obj.update(self.TEST_PLAIN_TEXT)
        self.assertEqual(test_obj.digest(test_obj.block_size), self.TEST_MAC_VALUE)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC,
            data=self.TEST_PLAIN_TEXT)
        self.assertEqual(test_obj.digest(test_obj.block_size), self.TEST_MAC_VALUE)

    def test_mac_calculate_hex(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC,)
        test_obj.update(self.TEST_PLAIN_TEXT)
        self.assertEqual(test_obj.hexdigest(test_obj.block_size), self.TEST_MAC_VALUE.hex())

    def test_mac_calculate_double(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC)
        test_obj.update(self.TEST_PLAIN_TEXT)
        test_obj.update(self.TEST_PLAIN_TEXT)
        self.assertEqual(test_obj.digest(test_obj.block_size), self.TEST_MAC_VALUE_DOUBLE)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC,
            data=self.TEST_PLAIN_TEXT)
        test_obj.update(self.TEST_PLAIN_TEXT)
        self.assertEqual(test_obj.digest(test_obj.block_size), self.TEST_MAC_VALUE_DOUBLE)

    def test_mac_calculate_double_padding(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC)
        test_obj.update(self.TEST_PLAIN_TEXT_NO_MUL)
        test_obj.update(self.TEST_PLAIN_TEXT_NO_MUL)
        self.assertEqual(test_obj.digest(test_obj.block_size), self.TEST_MAC_VALUE_DOUBLE_PAD)
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC)
        test_obj.update(self.TEST_PLAIN_TEXT_NO_MUL + self.TEST_PLAIN_TEXT_NO_MUL)
        self.assertEqual(test_obj.digest(test_obj.block_size), self.TEST_MAC_VALUE_DOUBLE_PAD)

    def test_mac_calculate_padding(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC)
        test_obj.update(self.TEST_PLAIN_TEXT_NO_MUL)
        self.assertEqual(test_obj.digest(test_obj.block_size), self.TEST_MAC_VALUE_PAD)

    def test_mac_calculate_raises(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.update('test_text_mac')
        self.assertTrue('invalid text data' in str(context.exception))
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC)
        with self.assertRaises(GOSTCipherError) as context:
            test_obj.update(self.TEST_PLAIN_TEXT)
            test_obj.digest(test_obj.block_size + 1)
        self.assertTrue('invalid message authentication code size' in str(context.exception))

    def test_iv(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.iv, self.TEST_INIT_VECT[len(self.TEST_INIT_VECT) - test_obj.block_size::])
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.iv, self.TEST_INIT_VECT[len(self.TEST_INIT_VECT) - test_obj.block_size::])
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.iv, self.TEST_INIT_VECT[len(self.TEST_INIT_VECT) - test_obj.block_size::])

    def test_counter(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)
        test_counter = self.TEST_INIT_VECT_CTR + b'\x00' * (test_obj.block_size // 2)
        test_counter = bytearray(test_counter)
        self.assertEqual(test_obj.counter, test_counter)

    def test_oid(self):
        test_obj = gostcrypto.gostcipher.new('kuznechik', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        self.assertEqual(test_obj.oid.__str__(), '1.2.643.7.1.1.5.2')
        self.assertEqual(test_obj.oid.digit, tuple([1, 2, 643, 7, 1, 1, 5, 2]))
        self.assertEqual(test_obj.oid.name, 'id-tc26-cipher-gostr3412-2015-kuznyechik')
        self.assertEqual(test_obj.oid.octet, bytearray([0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x05, 0x02]))


@pytest.mark.cipher
class TestGOST34132015Magma(unittest.TestCase):

    TEST_KEY = bytearray([
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    ])

    TEST_PLAIN_TEXT = bytearray([
        0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59,
        0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
        0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c,
        0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41,
    ])

    TEST_PLAIN_TEXT_NO_MUL = bytearray([
        0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59,
        0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
        0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c,
        0x89, 0x12, 0x40, 0x9b, 0x17,
    ]) 

    TEST_CIPHER_TEXT_ECB = bytearray([
        0x2b, 0x07, 0x3f, 0x04, 0x94, 0xf3, 0x72, 0xa0,
        0xde, 0x70, 0xe7, 0x15, 0xd3, 0x55, 0x6e, 0x48,
        0x11, 0xd8, 0xd9, 0xe9, 0xea, 0xcf, 0xbc, 0x1e,
        0x7c, 0x68, 0x26, 0x09, 0x96, 0xc6, 0x7e, 0xfb
    ])

    TEST_CIPHER_TEXT_CTR = bytearray([
        0x4e, 0x98, 0x11, 0x0c, 0x97, 0xb7, 0xb9, 0x3c,
        0x3e, 0x25, 0x0d, 0x93, 0xd6, 0xe8, 0x5d, 0x69,
        0x13, 0x6d, 0x86, 0x88, 0x07, 0xb2, 0xdb, 0xef,
        0x56, 0x8e, 0xb6, 0x80, 0xab, 0x52, 0xa1, 0x2d,
    ])

    TEST_CIPHER_TEXT_CTR_NO_MUL = bytearray([
        0x4e, 0x98, 0x11, 0x0c, 0x97, 0xb7, 0xb9, 0x3c,
        0x3e, 0x25, 0x0d, 0x93, 0xd6, 0xe8, 0x5d, 0x69,
        0x13, 0x6d, 0x86, 0x88, 0x07, 0xb2, 0xdb, 0xef,
        0x56, 0x8e, 0xb6, 0x80, 0xab,
    ])

    TEST_CIPHER_TEXT_CBC = bytearray([
        0x96, 0xd1, 0xb0, 0x5e, 0xea, 0x68, 0x39, 0x19,
        0xaf, 0xf7, 0x61, 0x29, 0xab, 0xb9, 0x37, 0xb9,
        0x50, 0x58, 0xb4, 0xa1, 0xc4, 0xbc, 0x00, 0x19,
        0x20, 0xb7, 0x8b, 0x1a, 0x7c, 0xd7, 0xe6, 0x67,
    ])

    TEST_CIPHER_TEXT_OFB = bytearray([
        0xdb, 0x37, 0xe0, 0xe2, 0x66, 0x90, 0x3c, 0x83,
        0x0d, 0x46, 0x64, 0x4c, 0x1f, 0x9a, 0x08, 0x9c,
        0xa0, 0xf8, 0x30, 0x62, 0x43, 0x0e, 0x32, 0x7e,
        0xc8, 0x24, 0xef, 0xb8, 0xbd, 0x4f, 0xdb, 0x05,
    ])

    TEST_CIPHER_TEXT_OFB_NO_MUL = bytearray([
        0xdb, 0x37, 0xe0, 0xe2, 0x66, 0x90, 0x3c, 0x83,
        0x0d, 0x46, 0x64, 0x4c, 0x1f, 0x9a, 0x08, 0x9c,
        0xa0, 0xf8, 0x30, 0x62, 0x43, 0x0e, 0x32, 0x7e,
        0xc8, 0x24, 0xef, 0xb8, 0xbd,
    ])

    TEST_CIPHER_TEXT_CFB = bytearray([
        0xdb, 0x37, 0xe0, 0xe2, 0x66, 0x90, 0x3c, 0x83,
        0x0d, 0x46, 0x64, 0x4c, 0x1f, 0x9a, 0x08, 0x9c,
        0x24, 0xbd, 0xd2, 0x03, 0x53, 0x15, 0xd3, 0x8b,
        0xbc, 0xc0, 0x32, 0x14, 0x21, 0x07, 0x55, 0x05,
    ])

    TEST_CIPHER_TEXT_CFB_NO_MUL = bytearray([
        0xdb, 0x37, 0xe0, 0xe2, 0x66, 0x90, 0x3c, 0x83,
        0x0d, 0x46, 0x64, 0x4c, 0x1f, 0x9a, 0x08, 0x9c,
        0x24, 0xbd, 0xd2, 0x03, 0x53, 0x15, 0xd3, 0x8b,
        0xbc, 0xc0, 0x32, 0x14, 0x21,
    ])

    TEST_INIT_VECT = bytearray([
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,  
        0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1,
    ])

    TEST_INIT_VECT_CBC = bytearray([
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,  
        0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1,  
        0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12,
    ])

    TEST_INIT_VECT_CTR = bytearray([
        0x12, 0x34, 0x56, 0x78,
    ])

    TEST_MAC_VALUE = bytearray([
        0x15, 0x4e, 0x72, 0x10, 0x20, 0x30, 0xc5, 0xbb,
    ])

    def test_ecb_encrypt(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_ECB)

    def test_ecb_decrypt(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_ECB), self.TEST_PLAIN_TEXT)

    def test_ctr_encrypt(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CTR)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CTR_NO_MUL)

    def test_ctr_encrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CTR)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CTR_NO_MUL)

    def test_ctr_decrypt(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CTR), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CTR_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)

    def test_ctr_decrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CTR), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CTR_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)

    def test_cbc_encrypt(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT_CBC)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CBC)

    def test_cbc_encrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CBC)

    def test_cbc_decrypt(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC,
            init_vect=self.TEST_INIT_VECT_CBC)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CBC), self.TEST_PLAIN_TEXT)

    def test_cbc_decrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CBC)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CBC), self.TEST_PLAIN_TEXT)

    def test_cfb_encrypt(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_CFB)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_CFB_NO_MUL)

    def test_cfb_decrypt(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CFB), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB,
            init_vect=self.TEST_INIT_VECT)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CFB_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)

    def test_cfb_decrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CFB), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CFB)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_CFB_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)

    def test_ofb_encrypt(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_OFB)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_OFB_NO_MUL)

    def test_ofb_encrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT), self.TEST_CIPHER_TEXT_OFB)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB)
        self.assertEqual(test_obj.encrypt(self.TEST_PLAIN_TEXT_NO_MUL), self.TEST_CIPHER_TEXT_OFB_NO_MUL)

    def test_ofb_decrypt(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_OFB), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_OFB_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)

    def test_ofb_decrypt_iv_default(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_OFB), self.TEST_PLAIN_TEXT)
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB)    
        self.assertEqual(test_obj.decrypt(self.TEST_CIPHER_TEXT_OFB_NO_MUL), self.TEST_PLAIN_TEXT_NO_MUL)

    def test_mac_calculate(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_MAC)
        test_obj.update(self.TEST_PLAIN_TEXT)                                             
        self.assertEqual(test_obj.digest(test_obj.block_size), self.TEST_MAC_VALUE)

    def test_iv(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_OFB,
            init_vect=self.TEST_INIT_VECT)
        self.assertEqual(test_obj.iv, self.TEST_INIT_VECT[len(self.TEST_INIT_VECT) - test_obj.block_size::])

    def test_counter(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_CTR,
            init_vect=self.TEST_INIT_VECT_CTR)
        test_counter = self.TEST_INIT_VECT_CTR + b'\x00' * (test_obj.block_size // 2)
        test_counter = bytearray(test_counter)
        self.assertEqual(test_obj.counter, test_counter)

    def test_oid(self):
        test_obj = gostcrypto.gostcipher.new('magma', self.TEST_KEY, gostcrypto.gostcipher.MODE_ECB)
        self.assertEqual(test_obj.oid.__str__(), '1.2.643.7.1.1.5.1')
        self.assertEqual(test_obj.oid.digit, tuple([1, 2, 643, 7, 1, 1, 5, 1]))
        self.assertEqual(test_obj.oid.name, 'id-tc26-cipher-gostr3412-2015-magma')
        self.assertEqual(test_obj.oid.octet, bytearray([0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x05, 0x01]))
        

if __name__ == '__main__':
    unittest.main()
