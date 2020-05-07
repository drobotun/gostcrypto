# pylint: disable=duplicate-code

#The GOST cryptographic functions.
#
#Author: Evgeny Drobotun (c) 2020
#License: MIT

"""
The object identifier encoding functions.

The module that implements functions for encoding and converting object
identifiers. The module includes the 'ObjectIdentifier' class, the
'GOSTOIDError' class, constants and several general functions.

Attributes:
    OBJECT_IDENTIFIER_TC26: A set of object identifiers (OIDs) of the Technical
      Committee for standardization "Cryptographic information protection"
      (TC 26).
"""
# pylint: enable=duplicate-code

OBJECT_IDENTIFIER_TC26 = {
    '1.2.643.7.1': 'id-tc26',
    '1.2.643.7.1.0': 'modules',
    '1.2.643.7.1.0.1': 'gostR3410-2012-ParamSetSyntax',
    '1.2.643.7.1.0.2': 'gostR3410-2012-PKISyntax',
    '1.2.643.7.1.0.3': 'gostR3410-2012-SignatureSyntax',
    '1.2.643.7.1.0.4': 'gostR3410-2012-EncryptionSyntax',
    '1.2.643.7.1.0.5': 'pkcs-12ruSyntax',
    '1.2.643.7.1.1': 'id-tc26-algorithms',
    '1.2.643.7.1.1.1': 'id-tc26-sign',
    '1.2.643.7.1.1.1.1': 'id-tc26-gost3410-12-256',
    '1.2.643.7.1.1.1.2': 'id-tc26-gost3410-12-512',
    '1.2.643.7.1.1.2': 'id-tc26-digest',
    '1.2.643.7.1.1.2.2': 'id-tc26-gost3411-12-256',
    '1.2.643.7.1.1.2.3': 'id-tc26-gost3411-12-512',
    '1.2.643.7.1.1.3': 'id-tc26-signwithdigest',
    '1.2.643.7.1.1.3.2': 'id-tc26-signwithdigest-gost3410-12-256',
    '1.2.643.7.1.1.3.3': 'id-tc26-signwithdigest-gost3410-12-512',
    '1.2.643.7.1.1.4': 'id-tc26-mac',
    '1.2.643.7.1.1.4.1': 'id-tc26-hmac-gost-3411-12-256',
    '1.2.643.7.1.1.4.2': 'id-tc26-hmac-gost-3411-12-512',
    '1.2.643.7.1.1.5': 'id-tc26-cipher',
    '1.2.643.7.1.1.5.1': 'id-tc26-cipher-gostr3412-2015-magma',
    '1.2.643.7.1.1.5.1.1': 'id-tc26-cipher-gostr3412-2015-magma-ctracpkm',
    '1.2.643.7.1.1.5.1.2': 'id-tc26-cipher-gostr3412-2015-magma-ctracpkm-omac',
    '1.2.643.7.1.1.5.2': 'id-tc26-cipher-gostr3412-2015-kuznyechik',
    '1.2.643.7.1.1.5.2.1': 'id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm',
    '1.2.643.7.1.1.5.2.2': 'id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm-omac',
    '1.2.643.7.1.1.6': 'id-tc26-agreement',
    '1.2.643.7.1.1.6.1': 'id-tc26-agreement-gost-3410-12-256',
    '1.2.643.7.1.1.6.2': 'id-tc26-agreement-gost-3410-12-512',
    '1.2.643.7.1.1.7': 'id-tc26-wrap',
    '1.2.643.7.1.1.7.1': 'id-tc26-wrap-gostr3412-2015-magma',
    '1.2.643.7.1.1.7.1.1': 'id-tc26-wrap-gostr3412-2015-magma-kexp15',
    '1.2.643.7.1.1.7.2': 'id-tc26-wrap-gostr3412-2015-kuznyechik',
    '1.2.643.7.1.1.7.2.1': 'id-tc26-wrap-gostr3412-2015-kuznyechik-kexp15',
    '1.2.643.7.1.2': 'id-tc26-constants',
    '1.2.643.7.1.2.1': 'id-tc26-sign-constants',
    '1.2.643.7.1.2.1.1': 'id-tc26-gost-3410-12-256-constants',
    '1.2.643.7.1.2.1.1.1': 'id-tc26-gost-3410-12-256-paramSetA',
    '1.2.643.7.1.2.1.1.2': 'id-tc26-gost-3410-12-256-paramSetB',
    '1.2.643.7.1.2.1.1.3': 'id-tc26-gost-3410-12-256-paramSetC',
    '1.2.643.7.1.2.1.1.4': 'id-tc26-gost-3410-12-256-paramSetD',
    '1.2.643.7.1.2.1.2': 'id-tc26-gost-3410-12-512-constants',
    '1.2.643.7.1.2.1.2.0': 'id-tc26-gost-3410-12-512-paramSetTest',
    '1.2.643.7.1.2.1.2.1': 'id-tc26-gost-3410-12-512-paramSetA',
    '1.2.643.7.1.2.1.2.2': 'id-tc26-gost-3410-12-512-paramSetB',
    '1.2.643.7.1.2.1.2.3': 'id-tc26-gost-3410-12-512-paramSetС',
    '1.2.643.7.1.2.2': 'id-tc26-digset-constants',
    '1.2.643.7.1.2.5': 'id-tc26-cipher-constants',
    '1.2.643.7.1.2.5.1': 'id-tc26-gost-28147-constants',
    '1.2.643.7.1.2.5.1.1': 'id-tc26-gost-28147-param-Z',
}

_TAG_OID: int = 0x06


def _len_int(value: int, num_bit: int) -> int:
    result = value.bit_length() // num_bit
    if result == 0:
        return 1
    if value.bit_length() % num_bit != 0:
        result = result + 1
    return result


def _len_oid_octet(value: int) -> bytearray:
    if value < 0x80:
        return bytearray(value.to_bytes(1, byteorder='big'))
    result = bytearray(_len_int(value, 8) + 1)
    result[0] = 0x80 | _len_int(value, 8)
    for i in range(_len_int(value, 8), 0, -1):
        result[i] = value & 0xff
        value = value >> 8
    return result


def _int_to_octet(value: int) -> bytearray:
    if value < 0x80:
        return bytearray(value.to_bytes(1, byteorder='big'))
    result = bytearray(_len_int(value, 7))
    for i in range(_len_int(value, 7) - 1, -1, -1):
        result[i] = value & 0x7F
        value = value >> 7
    result[0] = result[0] | 0x80
    return result


def _encode_octet(value: tuple) -> bytearray:
    result = bytearray()
    if value[0] == 0:
        if value[1] < 40:
            first_value = value[1]
        else:
            raise GOSTOIDError('invalid second SID value')
    elif value[0] == 1:
        if value[1] < 40:
            first_value = value[1] + 40
        else:
            raise GOSTOIDError('invalid second SID value')
    elif value[0] == 2:
        first_value = value[1] + 80
    else:
        raise GOSTOIDError('invalid first SID value')
    result = _int_to_octet(first_value)
    for iter_value in value[2:]:
        result = result + _int_to_octet(iter_value)
    return result


class ObjectIdentifier:
    """
    This class contains information about the object identifier.

    Attributes:
        name: Contain string with object identifier name.
        digit: Contain object identifiers as a tuple of integers.
        octet: Contain object identifier in the ASN.1 encoding.
    """

    def __init__(self, oid_value: str) -> None:
        """
        Initialize the OID object.

        Args:
            value: String  with the dotted representation of the OID.
        """
        self._oid_str = oid_value

    def __str__(self) -> str:
        """Return string with the dotted representation of the OID."""
        return self._oid_str

    @property
    def name(self) -> str:
        """
        Return object identifier name.

        Returns the names of object identifiers registered with the Technical
        Committee for standardization (TC 26) (defined in the
        'OBJECT_IDENTIFIER_TC26' constant). If there is no name assigned to the
        object identifier, an empty string is returned.
        """
        return OBJECT_IDENTIFIER_TC26.get(self._oid_str, '')

    @property
    def digit(self) -> tuple:
        """
        Return the object identifiers as a tuple of integers.

        If the object identifiers is incorrectly represented, an exception is
        thrown 'GOSTOIDError('invalid OID value')'.
        """
        try:
            result = tuple(int(item) for item in self._oid_str.split('.'))
        except ValueError:
            raise GOSTOIDError('invalid OID value')
        return result

    @property
    def octet(self) -> bytearray:
        """Return the object identifier in ASN.1 encoding."""
        preamble = bytearray()
        oid_octet = bytearray()
        oid_octet = _encode_octet(self.digit)
        preamble = (
            bytearray(_TAG_OID.to_bytes(1, byteorder='big'))
            + _len_oid_octet(len(oid_octet))
        )
        return preamble + oid_octet


class GOSTOIDError(Exception):
    """
    The exception class.

    This is a class that implements exceptions that can occur when input data
    is incorrect.
    """
