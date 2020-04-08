"""The module implementing the password-based key derivation function in accordance
   with R 50.1.111-2016.

   Author: Evgeny Drobotun (c) 2020
   License: MIT

   Usage:

       import gostcrypto

       pbkdf_obj = new(<'password'>, <'salt'>)
       result = pbkdf_obj.derive(32)

"""
import os
from sys import exit as sys_exit

from gostcrypto.gosthmac import R5011132016
from gostcrypto.utils import int_to_bytearray
from gostcrypto.utils import zero_fill
from gostcrypto.utils import add_xor

__all__ = ['R5011112016', 'new']

_BLOCK_SIZE = 64

def new(password, salt=None, counter=1000):
    """Creates a new object for the password-based key derivation function and returns it.

       Args:
          :password: Password that is a character string in Unicode UTF-8 encoding.
          :salt: Random value. If this argument is not passed to the function, the 'os.urandom'
             function is used to generate this value with the length of the generated value of
             32 bytes.
          :counter: Number of iterations. The default value is 1000.

       Return:
          New object for the password-based key derivation function.

       Exception:
          ValueError('invalid password value') - in case of invalid password value.
    """
    try:
        return R5011112016(password, salt, counter)
    except ValueError as err:
        print(err)
        sys_exit()

class R5011112016:
    """Class that implementing the calculating the password-based key derivation functione
       in accordance with R 50.1.111-2016.

       Methods:
          :derive(): returns a derived key as a byte object.
          :hexderive(): returns a derived key as a hexadecimal string.
          :clear(): clears the password value.

       Attributes:
          :salt: a byte object containing a random value (salt).
    """

    def __init__(self, password, salt, iterations):
        #Initialize the PBKDF object
        if not isinstance(password, (bytes, bytearray)):
            raise ValueError('ValueError: invalid password value')
        self._password = bytearray(password)
        password = zero_fill(len(password))
        if salt is None:
            self._salt = os.urandom(32)
        else:
            self._salt = bytearray(salt)
        self._iterations = iterations
        self._num_block = 0
        self._counter = 0
        self._hmac_obj = R5011132016('HMAC_GOSTR3411_2012_512', self._password)

    def __del__(self):
        #Delete the PBKDF object
        self.clear()

    def _u_first(self):
        #Primary calculation function U
        self._hmac_obj.reset()
        self._hmac_obj.update(self._salt + int_to_bytearray(self._counter, 4))
        return self._hmac_obj.digest()

    def _u_iter(self, u_prev):
        #Iterative calculation function U
        self._hmac_obj.reset()
        self._hmac_obj.update(u_prev)
        return self._hmac_obj.digest()

    def _f(self):
        #Iunction for calculating the PBKDF value once
        _t = self._u_first()
        internal = self._u_first()
        for _ in range(1, self._iterations):
            internal = self._u_iter(internal)
            _t = add_xor(_t, internal)
        return _t

    def _calculate_pbkdf(self, dk_len):
        #Function for final calculation of the PBKDF value
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
              ValueError('invalid size of the derived key') - in case of invalid size of the
                derived key.
        """
        if dk_len > (2 ** 32 - 1) * 64:
            raise ValueError('ValueError: invalid size of the derived key')
        return self._calculate_pbkdf(dk_len)[:dk_len]

    def hexderive(self, dk_len):
        """Returns a derived key as a hexadecimal string.

           Args:
              :dk_len: Required length of the output sequence (in bytes).

           Return:
              Derived key as a hexadecimal string with the length 'dk_len'.

           Exception:
              ValueError('invalid size of the derived key') - in case of invalid size of the
                 derived key.
        """
        if dk_len > (2 ** 32 - 1) * 64:
            raise ValueError('ValueError: invalid size of the derived key')
        return self._calculate_pbkdf(dk_len)[:dk_len].hex()

    def clear(self):
        """Сlears the password value.
        """
        self._password = zero_fill(len(self._password))

    @property
    def salt(self):
        """The byte object containing a random value (salt).
        """
        return self._salt
