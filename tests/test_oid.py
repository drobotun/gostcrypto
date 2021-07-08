import unittest
import pytest

import gostcrypto

from gostcrypto.gostoid import GOSTOIDError
from gostcrypto.gostoid import ObjectIdentifier

@pytest.mark.oid
class Test(unittest.TestCase):

    def test_oid(self):
        test_oid_obj = ObjectIdentifier('1.2.643.7.1.1.2.2')
        self.assertEqual(test_oid_obj.__str__(), '1.2.643.7.1.1.2.2')
        self.assertEqual(test_oid_obj.digit, tuple([1, 2, 643, 7, 1, 1, 2, 2]))
        self.assertEqual(test_oid_obj.name, 'id-tc26-gost3411-12-256')
        self.assertEqual(test_oid_obj.octet, bytearray([0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02,]))

    def test_oid_raises(self):
        test_oid_obj = ObjectIdentifier('1.b.643.7.1.1.2.2')
        with self.assertRaises(GOSTOIDError) as context:
            oid = test_oid_obj.digit
        self.assertTrue('invalid OID value' in str(context.exception))
        test_oid_obj = ObjectIdentifier('4.2.643.7.1.1.2.2')
        with self.assertRaises(GOSTOIDError) as context:
            oid = test_oid_obj.octet
        self.assertTrue('invalid first SID value' in str(context.exception))
        test_oid_obj = ObjectIdentifier('1.50.643.7.1.1.2.2')
        with self.assertRaises(GOSTOIDError) as context:
            oid = test_oid_obj.octet
        self.assertTrue('invalid second SID value' in str(context.exception))
        