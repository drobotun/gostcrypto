"""The module implementing the password-based key derivation function in accordance
with R 50.1.111-2016.

Author: Evgeny Drobotun (c) 2020
License: MIT
"""
import os

from gostcrypto.gosthmac import R5011132016
from gostcrypto.utils import int_to_bytearray
from gostcrypto.utils import zero_fill
from gostcrypto.utils import add_xor

__all__ = [
    'R5011112016',
    'new',
    'GOSTPBKDFError'
]

_BLOCK_SIZE = 64


def new(password, salt=None, counter=1000):
    """Creates a new object for the password-based key derivation function and
    returns it.

    Args:
    :password: Password that is a character string in Unicode UTF-8 encoding.
    :salt: Random value. If this argument is not passed to the function, the
    'os.urandom' function is used to generate this value with the length of the
    generated value of 32 bytes.
    :counter: Number of iterations. The default value is 1000.

    Return:
    New object for the password-based key derivation function.

    Exception:
    - GOSTPBKDFError('invalid password value') - if the password value is incorrect.
    - GOSTPBKDFError('invalid salt value') - if the salt value is incorrect.
    """
    return R5011112016(password, salt, counter)


class R5011112016:
    """Class that implementing the calculating the password-based key derivation
    function in accordance with R 50.1.111-2016.

    Methods:
    :derive(): returns a derived key as a byte object.
    :hexderive(): returns a derived key as a hexadecimal string.
    :clear(): clears the password value.

    Attributes:
    :salt: a byte object containing a random value (salt).
    """

    def __init__(self, password, salt, iterations):
        """Initialize the PBKDF object."""
        if not isinstance(password, (bytes, bytearray)):
            raise GOSTPBKDFError('invalid password value')
        self._password = bytearray(password)
        self._salt = salt
        if self._salt is None:
            self._salt = os.urandom(32)
        if not isinstance(self._salt, (bytes, bytearray)):
            password = zero_fill(password)
            self._password = zero_fill(self._password)
            raise GOSTPBKDFError('invalid salt value')
        self._salt = bytearray(self._salt)
        self._iterations = iterations
        self._num_block = 0
        self._counter = 0
        self._hmac_obj = R5011132016('HMAC_GOSTR3411_2012_512', self._password)
        password = zero_fill(password)

    def __del__(self):
        """Delete the PBKDF object."""
        self.clear()

    def _u_first(self):
        """Primary calculation function U."""
        self._hmac_obj.reset()
        self._hmac_obj.update(self._salt + int_to_bytearray(self._counter, 4))
        return self._hmac_obj.digest()

    def _u_iter(self, u_prev):
        """Iterative calculation function U."""
        self._hmac_obj.reset()
        self._hmac_obj.update(u_prev)
        return self._hmac_obj.digest()

    def _f(self):
        """Function for calculating the PBKDF value once."""
        _t = self._u_first()
        internal = self._u_first()
        for _ in range(1, self._iterations):
            internal = self._u_iter(internal)
            _t = add_xor(_t, internal)
        return _t

    def _calculate_pbkdf(self, dk_len):
        """Function for final calculation of the PBKDF value."""
        result = b''
        self._num_block = dk_len // _BLOCK_SIZE
        if dk_len % _BLOCK_SIZE != 0:
            self._num_block = self._num_block + 1
        for i in range(1, self._num_block + 1):
            self._counter = i
            result = result + self._f()
        return result

    def derive(self, dk_len):
        """Returns a derived key as a byte object.

        Args:
        :dk_len: Required length of the output sequence (in bytes).

        Return:
        Derived key as a byte object with the length 'dk_len'.

        Exception:
        - GOSTPBKDFError('invalid size of the derived key') - if the size of the derived
        key is incorrect.
        """
        if dk_len > (2 ** 32 - 1) * 64:
            raise GOSTPBKDFError('invalid size of the derived key')
        return self._calculate_pbkdf(dk_len)[:dk_len]

    def hexderive(self, dk_len):
        """Returns a derived key as a hexadecimal string.

        Args:
        :dk_len: Required length of the output sequence (in bytes).

        Return:
        Derived key as a hexadecimal string with the length 'dk_len'.

        Exception:
        - GOSTPBKDFError('invalid size of the derived key') - if the size of the derived
        key is incorrect.
        """
        if dk_len > (2 ** 32 - 1) * 64:
            raise GOSTPBKDFError('invalid size of the derived key')
        return self._calculate_pbkdf(dk_len)[:dk_len].hex()

    def clear(self):
        """Сlears the password value."""
        self._password = zero_fill(self._password)

    @property
    def salt(self):
        """The byte object containing a random value (salt)."""
        return self._salt


class GOSTPBKDFError(Exception):
    """The class that implements exceptions that may occur when module class methods
    are used.
    """
