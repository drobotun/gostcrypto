#The GOST cryptographic functions.
#
#Author: Evgeny Drobotun (c) 2020
#License: MIT

"""
The GOST hash-based message authentication code functions.

The module implementing the calculating the HMAC message authentication code
in accordance with R 50.1.113-2016.  The module includes the R5011132016 class,
the GOSTHMACError class and several general functions.
"""
from copy import deepcopy

from gostcrypto.gosthash import GOST34112012
from gostcrypto.utils import zero_fill
from gostcrypto.utils import add_xor

__all__ = (
    'R5011132016',
    'new',
    'GOSTHMACError'
)

_KEY_SIZE: int = 64

_I_PAD: bytearray = bytearray([
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
])

_O_PAD: bytearray = bytearray([
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
])


def new(name: str, key: bytearray, **kwargs) -> 'R5011132016':
    """
    Create a new authentication code calculation object and returns it.

    Parameters
    - name: name of the authentication code calculation mode
    ('HMAC_GOSTR3411_2012_256' or 'HMAC_GOSTR3411_2012_512').
    - key: authentication key.

    Keyword args
    - data: the data from which to get the HMAC (as a byte object).  If this
    argument is passed to a function, you can immediately use the 'digest'
    (or 'hexdigest') method to calculate the HMAC value after calling 'new'.
    If the argument is not passed to the function, then you must use the
    'update(data)' method before the 'digest' (or 'hexdigest') method.

    Return: new authentication code calculation object.

    Exception
    - GOSTHMACError('GOSTHMACError: unsupported mode'): in case of unsupported
    mode.
    - GOSTHMACError('GOSTHMACError: invalid key value'): in case of invalid key
    value.
    - GOSTHMACError('GOSTHMACError: invalid data value'): in case where the
    data is not byte object.
    """
    data = kwargs.get('data', bytearray(b''))
    return R5011132016(name, key, data)


class R5011132016:
    """
    Class that implementing the calculating the HMAC.

    Methods
    - update(): update the HMAC object with the bytes-like object.
    - digest(): getting the authentication code.
    - clear(): clears the key value.
    - copy(): returns a copy (“clone”) of the HMAC object.

    Attributes
    - digest_size: an integer value of the size of the resulting HMAC digest
    in bytes.
    - block_size: an integer value the internal block size of the hash
    algorithm in bytes.
    - name: a text string is the name of the authentication code calculation
    algorithm.
    """

    def __init__(self, name: str, key: bytearray, data: bytearray) -> None:
        """Initialize the HMAC object."""
        if name not in ('HMAC_GOSTR3411_2012_256', 'HMAC_GOSTR3411_2012_512'):
            raise GOSTHMACError('GOSTHMACError: unsupported mode')
        if (not isinstance(key, (bytes, bytearray))) or len(key) > _KEY_SIZE:
            raise GOSTHMACError('GOSTHMACError: invalid key value')
        if len(key) < _KEY_SIZE:
            add = bytearray(_KEY_SIZE - len(key))
            self._key = key + add
            self._key = bytearray(self._key)
        elif len(key) == _KEY_SIZE:
            self._key = key
        key = bytearray(len(key))
        if name == 'HMAC_GOSTR3411_2012_256':
            self._hasher_obj = GOST34112012('streebog256', data=bytearray(b''))
        elif name == 'HMAC_GOSTR3411_2012_512':
            self._hasher_obj = GOST34112012('streebog512', data=bytearray(b''))
        self._counter = 0
        if data != bytearray(b''):
            self.update(data)

    def __del__(self) -> None:
        """
        Delete the HMAC object.

        When deleting an instance of a class, it clears the hasher object to
        remove the key value from memory.
        """
        if hasattr(self, '_hasher_obj'):
            self.clear()

    def update(self, data: bytearray) -> None:
        """
        Update the HMAC object with the bytes-like object.

        Parameters
        - data: the message for which want to calculate the authentication code.
        Repeated calls are equivalent to a single call with the concatenation
        of all the arguments: 'm.update(a)'; 'm.update(b)' is equivalent to
        'm.update(a+b)'.

        Exception
        - GOSTHMACError('GOSTHMACError: invalid data value'): in case where the
        data is not byte object.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise GOSTHMACError('GOSTHMACError: invalid data value')
        self._counter = self._counter + 1
        if self._counter == 1:
            self._hasher_obj.update(add_xor(self._key, _I_PAD) + data)
        elif self._counter != 1:
            self._hasher_obj.update(data)

    def digest(self) -> bytearray:
        """
        Return the HMAC message authentication code.

        This method is called after calling the 'update ()' method.

        Return: HMAC message authentication code as a byte object.
        """
        fin_hasher_obj = GOST34112012(self._hasher_obj.name, data=bytearray(b''))
        fin_hasher_obj.update(add_xor(self._key, _O_PAD) + self._hasher_obj.digest())
        result = fin_hasher_obj.digest()
        fin_hasher_obj.reset()
        return result

    def hexdigest(self) -> str:
        """
        Return the HMAC message authentication code.

        This method is called after calling the 'update ()' method.

        Return: HMAC message authentication code as a hexadecimal string.
        """
        return self.digest().hex()

    def copy(self) -> 'R5011132016':
        """
        Return a duplicate (“clone”) of the HMAC object.

        This can be used to efficiently compute the digests of data sharing
        a common initial substring.
        """
        return deepcopy(self)

    def reset(self) -> None:
        """Reset the values of all class attributes."""
        self._hasher_obj.reset()
        self._counter = 0

    def clear(self) -> None:
        """Сlear the key value."""
        self._hasher_obj.reset()
        self._key = zero_fill(self._key)

    @property
    def digest_size(self) -> int:
        """
        Return the size of the resulting hash in bytes.

        For the 'streebog256' algorithm, this value is 32, for the 'streebog512'
        algorithm, this value is 64.
        """
        return self._hasher_obj.digest_size

    @property
    def block_size(self) -> int:
        """
        Return the value of the internal block size of the hashing algorithm.

        For the 'streebog256' algorithm and the 'streebog512' algorithm, this
        value is 64.
        """
        return self._hasher_obj.block_size

    @property
    def name(self) -> str:
        """
        Return text string is the name of the HMAC calculation algorithm.

        Respectively 'HMAC_GOSTR3411_2012_256' or 'streebog512'.
        """
        if self._hasher_obj.name == 'streebog512':
            result = 'HMAC_GOSTR3411_2012_512'
        else:
            result = 'HMAC_GOSTR3411_2012_256'
        return result


class GOSTHMACError(Exception):
    """
    The class that implements exceptions.

    Exceptions
    - unsupported mode.
    - invalid key value.
    - invalid data value.
    """

    pass
