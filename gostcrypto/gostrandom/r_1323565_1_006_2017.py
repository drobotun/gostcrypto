"""The module that implements pseudo-random sequence generation in accordance with
R 1323565.1.006-2017.

Author: Evgeny Drobotun (c) 2020
License: MIT
"""
import os

from gostcrypto.gosthash import GOST34112012
from gostcrypto.utils import bytearray_to_int
from gostcrypto.utils import int_to_bytearray
from gostcrypto.utils import zero_fill
from gostcrypto.utils import check_value

__all__ = [
    'R132356510062017',
    'new',
    'GOSTRandomError',
    'SIZE_S_384',
    'SIZE_S_320',
    'SIZE_S_256'
]

SIZE_S_384 = 48  #The size of the initial filling (seed) is 384 bits
SIZE_S_320 = 40  #The size of the initial filling (seed) is 320 bits
SIZE_S_256 = 32  #The size of the initial filling (seed) is 256 bits

_SIZE_M = 64
_SIZE_H = 64


def new(rand_size, rand_k=None, size_s=SIZE_S_384):
    """Creates a new pseudo-random sequence generation object and returns it.

    Args:

    :rand_size: Size of the generated random variable (in bytes).
    :rand_k: Initial filling (seed). If this argument is not passed to the function,
    the 'os.urandom' function is used to generate the initial filling.
    :size_s: Size of the initial filling (in bytes).

    Return:
    New object of generate random value.

    Exception:
    - GOSTRandomError('invalid seed value') - in case of invalid value of  initial
    filling.
    """
    return R132356510062017(rand_size, rand_k, size_s)


class R132356510062017:
    """Class that implements pseudo-random sequence generation in accordance with
    R 1323565.1.006-2017.

    Methods:
    :random(): generating the next value from a pseudo-random sequence.
    :reset(): resetting the counter and setting a new initial filling.
    :clear(): clearing the counter value.
    """
    def __init__(self, rand_size, rand_k, size_s):
        """Initialize the random object."""
        self._size_s = size_s
        if rand_k is None:
            self._rand_u = os.urandom(self._size_s) + b'\x00' * (_SIZE_M - self._size_s - 1)
            self._rand_u = bytearray(self._rand_u)
        else:
            if not check_value(rand_k, self._size_s):
                raise GOSTRandomError('invalid seed value')
            self._rand_u = rand_k + b'\x00' * (_SIZE_M - self._size_s - 1)
            self._rand_u = bytearray(self._rand_u)
        self._q = rand_size // _SIZE_H
        self._r = rand_size % _SIZE_H
        self._limit = 2 ** (_SIZE_M - self._size_s)
        self._hash_obj = GOST34112012('streebog512', data=b'')

    def __del__(self):
        """Delete the random object."""
        self.clear()

    def _inc_rand_u(self):
        """Increasing the value of the generation counter."""
        self._rand_u = bytearray_to_int(self._rand_u) + 1 % (2 ** (_SIZE_M - 1))
        self._rand_u = int_to_bytearray(self._rand_u, _SIZE_M - 1)

    def random(self):
        """Generating the next value from a pseudo-random sequence.

        Return:
        New random value.

        Exception:
        - GOSTRandomError ('exceeded the limit value of the counter') - when the counter
        limit is exceeded.
        - GOSTRandomError('the seed value is zero') - if the seed value is zero.
        """
        if bytearray_to_int(self._rand_u[:self._size_s]) == 0:
            raise GOSTRandomError('the seed value is zero')
        i = self._q
        result = bytearray(0)
        while i > 0:
            if bytearray_to_int(self._rand_u[self._size_s::]) >= self._limit:
                self._rand_u = zero_fill(self._rand_u)
                raise GOSTRandomError('exceeded the limit value of the counter')
            self._inc_rand_u()
            self._hash_obj.update(self._rand_u)
            rand_c = self._hash_obj.digest()
            self._hash_obj.reset()
            result = result + rand_c
            i = i - 1
        if self._r != 0:
            if bytearray_to_int(self._rand_u[self._size_s::]) >= self._limit:
                self._rand_u = zero_fill(self._rand_u)
                raise GOSTRandomError('exceeded the limit value of the counter')
            self._inc_rand_u()
            self._hash_obj.update(self._rand_u)
            rand_c = self._hash_obj.digest()
            self._hash_obj.reset()
            result = result + rand_c[_SIZE_H - self._r:_SIZE_H:]
        return result

    def reset(self, rand_k=None):
        """Resetting the counter and setting a new initial filling.

        Args:
        :rand_k: New initial filling (seed). If this argument is not passed to the
        function, the 'os.urandom' function is used to generate the initial filling.

        Exception:
        - GOSTRandomError('invalid seed value') - in case of invalid size of  initial
        filling.
        """
        if rand_k is None:
            self._rand_u = os.urandom(self._size_s) + b'\x00' * (_SIZE_M - self._size_s - 1)
            self._rand_u = bytearray(self._rand_u)
        else:
            if not check_value(rand_k, self._size_s):
                raise GOSTRandomError('invalid seed value')
            self._rand_u = rand_k + b'\x00' * (_SIZE_M - self._size_s - 1)
            self._rand_u = bytearray(self._rand_u)
        self._hash_obj.reset()

    def clear(self):
        """Clearing the counter value."""
        self._rand_u = zero_fill(self._rand_u)


class GOSTRandomError(Exception):
    """The class that implements exceptions that may occur when module class methods
    are used.
    """
