"""The module implementing the calculating the HMAC message authentication code in
accordance with R 50.1.113-2016.

Author: Evgeny Drobotun (c) 2020
License: MIT
"""
from copy import deepcopy

from gostcrypto.gosthash import GOST34112012
from gostcrypto.utils import zero_fill
from gostcrypto.utils import add_xor

__all__ = [
    'R5011132016',
    'new',
    'GOSTHMACError'
]

_KEY_SIZE = 64

"""Сonstant 'ipad' (in accordance with RFC 2104)."""
_I_PAD = bytearray([
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
])

"""Сonstant 'opad' (in accordance with RFC 2104)."""
_O_PAD = bytearray([
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
])


def new(name, key):
    """Creates a new authentication code calculation object and returns it.

    Args:
    :name: Name of the authentication code calculation mode ('HMAC_GOSTR3411_2012_256'
        or 'HMAC_GOSTR3411_2012_512').
    :key: Authentication key.

    Return:
    New authentication code calculation object.

    Exception:
    GOSTHMACError('unsupported mode') - in case of unsupported mode.
    GOSTHMACError('invalid key value') - in case of invalid key value.
    """
    return R5011132016(name, key)


class R5011132016:
    """Class that implementing the calculating the HMAC message authentication
    code in accordance with R 50.1.113-2016.

    Methods:
    :update(): update the HMAC object with the bytes-like object.
    :digest(): getting the authentication code.
    :clear(): clears the key value.
    :copy(): returns a copy (“clone”) of the HMAC object.

    Attributes:
    :digest_size: an integer value of the size of the resulting HMAC digest in bytes.
    :block_size: an integer value the internal block size of the hash algorithm in bytes.
    :name: a text string is the name of the authentication code calculation algorithm.
    """

    def __init__(self, name, key):
        """Initialize the HMAC object."""
        if name not in ('HMAC_GOSTR3411_2012_256', 'HMAC_GOSTR3411_2012_512'):
            raise GOSTHMACError('unsupported mode')
        if (not isinstance(key, (bytes, bytearray))) or len(key) > _KEY_SIZE:
            raise GOSTHMACError('invalid key value')
        if len(key) < _KEY_SIZE:
            add = bytearray(_KEY_SIZE - len(key))
            self._key = key + add
            self._key = bytearray(self._key)
        elif len(key) == _KEY_SIZE:
            self._key = key
        key = bytearray(len(key))
        if name == 'HMAC_GOSTR3411_2012_256':
            self._hasher_obj = GOST34112012('streebog256', data=b'')
        elif name == 'HMAC_GOSTR3411_2012_512':
            self._hasher_obj = GOST34112012('streebog512', data=b'')
        self._counter = 0

    def __del__(self):
        """Delete the HMAC object."""
        if hasattr(self, '_hasher_obj'):
            self.clear()

    def update(self, data):
        """Update the HMAC object with the bytes-like object.

        Args:
        :data: The message for which want to calculate the authentication code.
        Repeated calls are equivalent to a single call with the concatenation of
        all the arguments: 'm.update(a)'; 'm.update(b)' is equivalent to
        'm.update(a+b)'.
        """
        self._counter = self._counter + 1
        if self._counter == 1:
            self._hasher_obj.update(add_xor(self._key, _I_PAD) + data)
        elif self._counter != 1:
            self._hasher_obj.update(data)

    def digest(self):
        """Returns the HMAC message authentication code."""
        fin_hasher_obj = GOST34112012(self._hasher_obj.name, data=b'')
        fin_hasher_obj.update(add_xor(self._key, _O_PAD) + self._hasher_obj.digest())
        result = fin_hasher_obj.digest()
        fin_hasher_obj.reset()
        return result

    def hexdigest(self):
        """Returns the HMAC message authentication code as a hexadecimal string."""
        return self.digest().hex()

    def copy(self):
        """Returns a copy (“clone”) of the HMAC object.

        This can be used to efficiently compute the digests of data sharing a common
        initial substring.
        """
        return deepcopy(self)

    def reset(self):
        """Resets the values of all class attributes."""
        self._hasher_obj.reset()
        self._counter = 0

    def clear(self):
        """Сlears the key value."""
        self._hasher_obj.reset()
        self._key = zero_fill(self._key)

    @property
    def digest_size(self):
        """An integer value of the size of the resulting HMAC digest in bytes."""
        return self._hasher_obj.digest_size

    @property
    def block_size(self):
        """An integer value the internal block size of the hash algorithm in bytes.

         For the 'streebog256' algorithm and the 'streebog512' algorithm, this value
         is 64.
        """
        return self._hasher_obj.block_size

    @property
    def name(self):
        """A text string is the name of the authentication code calculation
        algorithm.
        """
        if self._hasher_obj.name == 'streebog256':
            result = 'HMAC_GOSTR3411_2012_256'
        else:
            result = 'HMAC_GOSTR3411_2012_512'
        return result


class GOSTHMACError(Exception):
    """The class that implements exceptions that may occur when module class methods
    are used.
    """
