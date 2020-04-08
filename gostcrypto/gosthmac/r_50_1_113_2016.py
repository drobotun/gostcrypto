"""The module implementing the calculating the HMAC message authentication code in
   accordance with R 50.1.113-2016.

   Author: Evgeny Drobotun (c) 2020
   License: MIT

   Usage:
    - getting a HMAC for a string:

        import gostcrypto

        hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256')
        hmac_obj.update(b'<string>')
        result = hmac_obj.hexdigest()

    - getting a HMAC for a file:

        import gostcrypto

        #The 'buffer_size' must be a multiple of 64
        buffer_size = 128
        hmac_obj = gostcrypto.gosthash.new('HMAC_GOSTR3411_2012_256')
        with open(<'file path'>, 'rb') as file:
            buffer = file.read(buffer_size)
            while len(buffer) > 0:
                hmac_obj.update(buffer)
                buffer = file.read(buffer_size)
        result = hmac_obj.hexdigest()

"""
from sys import exit as sys_exit
from copy import deepcopy

from gostcrypto.gosthash import GOST34112012
from gostcrypto.utils import zero_fill
from gostcrypto.utils import add_xor

__all__ = ['R5011132016', 'new']

_KEY_SIZE = 64

#Сonstant 'ipad' (in accordance with RFC 2104)
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

#Сonstant 'opad' (in accordance with RFC 2104)
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
          ValueError('unsupported mode') - in case of unsupported mode.
          ValueError('invalid key size') - in case of invalid key size.
    """
    try:
        return R5011132016(name, key)
    except ValueError as err:
        print(err)
        sys_exit()

class R5011132016:
    """Class that implementing the calculating the HMAC message authentication code in
       accordance with R 50.1.113-2016.

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
        #Initialize the HMAC object
        if name not in ('HMAC_GOSTR3411_2012_256', 'HMAC_GOSTR3411_2012_512'):
            raise ValueError('ValueError: unsupported mode')
        if len(key) < _KEY_SIZE:
            add = bytearray(_KEY_SIZE - len(key))
            self._key = key + add
            self._key = bytearray(self._key)
        elif len(key) == _KEY_SIZE:
            self._key = key
        else:
            key = zero_fill(len(key))
            raise ValueError('ValueError: invalid key size')
        key = bytearray(len(key))
        if name == 'HMAC_GOSTR3411_2012_256':
            self._hasher_obj = GOST34112012('streebog256')
        elif name == 'HMAC_GOSTR3411_2012_512':
            self._hasher_obj = GOST34112012('streebog512')
        self._counter = 0

    def __del__(self):
        #Delete the HMAC object
        if hasattr(self, '_hasher_obj'):
            self.clear()

    def update(self, data):
        """Update the HMAC object with the bytes-like object.

           Args:
             :data: The message for which want to calculate the authentication code. Repeated
                calls are equivalent to a single call with the concatenation of all the
                arguments: m.update(a); m.update(b) is equivalent to m.update(a+b).
        """
        self._counter = self._counter + 1
        if self._counter == 1:
            self._hasher_obj.update(add_xor(self._key, _I_PAD) + data)
        elif self._counter != 1:
            self._hasher_obj.update(data)

    def digest(self):
        """Returns the HMAC message authentication code.
        """
        fin_hasher_obj = GOST34112012(self._hasher_obj.name)
        fin_hasher_obj.update(add_xor(self._key, _O_PAD) + self._hasher_obj.digest())
        result = fin_hasher_obj.digest()
        fin_hasher_obj.reset()
        return result

    def hexdigest(self):
        """Returns the HMAC message authentication code as a hexadecimal string.
        """
        fin_hasher_obj = GOST34112012(self._hasher_obj.name)
        fin_hasher_obj.update(add_xor(self._key, _O_PAD) + self._hasher_obj.digest())
        result = fin_hasher_obj.digest()
        fin_hasher_obj.reset()
        return result.hex()

    def copy(self):
        """Returns a copy (“clone”) of the HMAC object. This can be used to efficiently compute
           the digests of data sharing a common initial substring.
        """
        return deepcopy(self)

    def reset(self):
        """Resets the values of all class attributes.
        """
        self._hasher_obj.reset()
        self._counter = 0

    def clear(self):
        """Сlears the key value.
        """
        self._hasher_obj.reset()
        self._key = zero_fill(_KEY_SIZE)

    @property
    def digest_size(self):
        """An integer value of the size of the resulting HMAC digest in bytes.
        """
        return self._hasher_obj.digest_size

    @property
    def block_size(self):
        """An integer value the internal block size of the hash algorithm in bytes.
           For the 'streebog256' algorithm and the 'streebog512' algorithm,
           this value is 64.
        """
        return self._hasher_obj.block_size

    @property
    def name(self):
        """A text string is the name of the authentication code calculation algorithm.
        """
        if self._hasher_obj.name == 'streebog256':
            result = 'HMAC_GOSTR3411_2012_256'
        else:
            result = 'HMAC_GOSTR3411_2012_512'
        return result
