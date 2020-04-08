"""The module that implements various block encryption modes (ECB, CBC, CFB, OFB, CTR and
   MAC according to GOST 34.13-2015.

   Author: Evgeny Drobotun (c) 2020
   License: MIT

   Usage:
    - encrypting a string:

        import gostcrypto

        CIPHER_KEY = bytearray([
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        ])

        cipher = gostcrypto.gostcipher.new('kuznechik',
                                            CIPHER_KEY,
                                            gostcrypto.gostcipher.MODE_ECB)
        cipher_string = cipher.encrypt(b'<plain string>')

    - encrypting a file:

        import gostcrypto

        CIPHER_KEY = bytearray([
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        ])

        CIPHER_IV = bytearray([
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0,
        ])

        cipher = gostcrypto.gostcipher.new('kuznechik',
                                            CIPHER_KEY,
                                            gostcrypto.gostcipher.MODE_CTR,
                                            init_vect=CIPHER_IV)

        #The 'buffer_size' must be a multiple of the block size
        buffer_size = 128
        file_in = open('<path to the plain text file>', 'rb')
        file_out = open('<path to the encrypted text file>', 'wb')
        buffer = file_in.read(buffer_size)
        while len(buffer) > 0:
            block = cipher.decrypt(buffer)
            file_out.write(block)
            buffer = file_in.read(buffer_size)

    - calculating MAC of the file:

        import gostcrypto

        CIPHER_KEY = bytearray([
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        ])

        #The 'buffer_size' must be a multiple of the block size
        buffer_size = 128
        cipher = gostcrypto.gostcipher.new('kuznechik',
                                           CIPHER_KEY,
                                           gostcrypto.gostcipher.MODE_MAC,
                                           pad_mode=gostcrypto.gostcipher.PAD_MODE_3)
        file_in = open('<path to the file to calculate the MAC>', 'rb')
        buffer = file_in.read(buffer_size)
        while len(buffer) > 0:
            block = cipher.update(buffer)
            buffer = file_in.read(buffer_size)
        mac_result = cipher.digest(cipher.block_size)
"""

from sys import exit as sys_exit
from copy import deepcopy

from gostcrypto.utils import add_xor
from gostcrypto.utils import int_to_bytearray
from gostcrypto.utils import bytearray_to_int
from gostcrypto.utils import zero_fill
from gostcrypto.utils import msb

from .gost_34_12_2015 import GOST34122015Kuznechik
from .gost_34_12_2015 import GOST34122015Magma

__all__ = ['GOST34132015', 'new',
           'MODE_ECB', 'MODE_CBC',
           'MODE_CFB', 'MODE_OFB',
           'MODE_CTR', 'MODE_MAC',
           'PAD_MODE_1', 'PAD_MODE_2',
           'PAD_MODE_3']

MODE_ECB = 0x01 #Electronic Codebook mode
MODE_CBC = 0x02 #Cipher Block Chaining mode
MODE_CFB = 0x03 #Cipher Feedback mode
MODE_OFB = 0x05 #OutputFeedback mode
MODE_CTR = 0x06 #Counter mode
MODE_MAC = 0xff #Message Authentication Code algorithm

PAD_MODE_1 = 0x800000f0
PAD_MODE_2 = 0x800000f1
PAD_MODE_3 = 0x800000f2

_KEY_SIZE = 32

_B_64 = bytearray([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b,
])

_B_128 = bytearray([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
])

def new(algorithm, key, mode, **kwargs):
    """Creates a new ciphering object and returns it.

       Args:
          :algorithm: The string with the name of the ciphering algorithm
             of the GOST R 34.12-201 ('kuznechik' with block size 128 bit
             or 'magma' with block size 64 bit).
          :key: Byte object with 256-bit encryption key.
          :mode: Mode of operation of the block encryption algorithm (valid
             value: MODE_CBC, MODE_CFB, MODE_CTR, MODE_ECB, MODE_OFB or MODE_MAC).
       Keyword args:
          :init_vect: Byte object with initialization vector. Used in CTR, OFB,
             CBC and CFB modes. For CTR mode, the initialization vector length
             is equal to half the block size. For CBC, OFB and CFB modes, it
             is a multiple of the block size (the default value is 'None').
          :pad_mode: Padding mode for ECB, CBC, and MAC modes . For ECB and CBC modes,
             the acceptable values are PAD_MODE_1 and PAD_MODE_2. For MAC mode,
             the acceptable value is PAD_MODE_3 (the default value is PAD_MODE_1).

       Return:
          New ciphering object.

       Exception:
          ValueError('unsupported algorithm') - in case of invalid value 'algorithm'.
          ValueError('invalid key size') - in case of invalid key value.
          ValueError('invalid key value') - in case of invalid key value.
          ValueError('invalid IV value') - in case of invalid initialization vector value.
    """
    init_vect = kwargs.get('init_vect', None)
    pad_mode = kwargs.get('pad_mode', PAD_MODE_1)
    try:
        cipher_obj = GOST34132015(algorithm, key, mode,\
                                  init_vect=init_vect,\
                                  pad_mode=pad_mode)
        return cipher_obj
    except ValueError as err:
        print(err)
        sys_exit()

class GOST34132015:
    """Сlass that implements various block encryption modes in accordance with
       GOST 34.13-2015.

       Methods:
          :decrypt(): Decrypting a ciphertext.
          :encrypt(): Encrypting a plaintext.
          :update(): Update the MAC object with the bytes-like object.
          :digest(): Calculating the Message authentication code of the data passed to the
             'update()' method so far.
          :hexdigest(): Calculating the Message authentication code of the data passed to the
             'update()' method so far an return it of the hexadecimal.
          :clear(): Сlearing the values of iterative encryption keys.

       Attributes:
          :iv:  The initial value which will be used to start a cipher feedback mode.
          :counter: Counter blocks.
          :block_size: An integer value the internal block size of the cipher algorithm in bytes.
    """
    #pylint: disable=too-many-instance-attributes
    def __init__(self, algorithm, key, mode, **kwargs):
        #Initialize the ciphering object
        if not isinstance(key, (bytes, bytearray)):
            raise ValueError('ValueError: invalid key value')
        if len(key) != _KEY_SIZE:
            raise ValueError('ValueError: invalid key size')
        if not algorithm in ('magma', 'kuznechik'):
            key = zero_fill(len(key))
            raise ValueError('ValueError: unsupported algorithm')
        if algorithm == 'kuznechik':
            self._cipher_obj = GOST34122015Kuznechik(key)
        elif algorithm == 'magma':
            self._cipher_obj = GOST34122015Magma(key)
        self._mode = mode
        self._pad_mode = kwargs.get('pad_mode')
        self._init_vect = kwargs.get('init_vect')
        if mode in (MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR):
            if not isinstance(self._init_vect, (bytes, bytearray)):
                self.clear()
                raise ValueError('ValueError: invalid IV value')
            self._init_vect = bytearray(self._init_vect)
        if mode == MODE_CTR:
            self._counter = kwargs.get('init_vect') + b'\x00' * (self._cipher_obj.block_size // 2)
            self._counter = bytearray(self._counter)
        if mode == MODE_MAC:
            value_r = self._cipher_obj.encrypt(self._cipher_obj.block_size * b'\x00')
            self._key_1, self._key_2 = self._get_mac_key(value_r)
            self._buff = bytearray(self._cipher_obj.block_size)
            self._prev_mac = bytearray(self._cipher_obj.block_size)
            self._cur_mac = bytearray(self._cipher_obj.block_size)
        #pylint: enable=too-many-instance-attributes

    def __del__(self):
        #Delete the ciphering object
        self.clear()

    def _get_num_block(self, data):
        #Returns the number of blocks in the data
        return len(data) // self.block_size

    def _get_pad_size(self, data):
        #Returns the padding size
        if len(data) < self.block_size:
            result = self.block_size - len(data)
        elif len(data) % self.block_size == 0:
            result = 0
        else:
            result = self.block_size - len(data) % self.block_size
        return result

    def _pad_mode_1(self, data):
        #Setting of padding MODE_PAD_1
        return data + b'\x00' * self._get_pad_size(data)

    def _pad_mode_2(self, data):
        #Setting of padding MODE_PAD_2
        return data + b'\x80' + b'\x00' * (self.block_size + self._get_pad_size(data) - 1)

    def _pad_mode_3(self, data):
        #Setting of padding MODE_PAD_3
        if self._get_pad_size(data) == 0:
            result = data
        else:
            result = data + b'\x80' + b'\x00' * (self._get_pad_size(data) - 1)
        return result

    def _set_padding(self, data):
        #Selecting and setting padding
        if self._pad_mode == PAD_MODE_1:
            result = self._pad_mode_1(data)
        elif self._pad_mode == PAD_MODE_2:
            result = self._pad_mode_2(data)
        elif self._pad_mode == PAD_MODE_3:
            result = self._pad_mode_3(data)
        return result

    def _inc_ctr(self, ctr):
        #Increasing the counter value in CTR mode
        internal = 0
        bit = bytearray(self.block_size)
        bit[self.block_size - 1] = 0x01
        for i in range(self.block_size):
            internal = ctr[i] + bit[i] + (internal << 8)
            ctr[i] = internal & 0xff
        return ctr

    def _get_mac_key(self, value_r):
        #Generating final keys for MAC mode
        if self.block_size == 16:
            value_b = _B_128
        elif self.block_size == 8:
            value_b = _B_64
        if msb(value_r) == 0:
            int_value = bytearray_to_int(value_r) << 1
            key_1 = int_to_bytearray(int_value, self.block_size)
        else:
            int_value = bytearray_to_int(value_r) << 1
            key_1 = add_xor(int_to_bytearray(int_value, self.block_size), value_b)
        if msb(key_1) == 0:
            int_value = bytearray_to_int(key_1) << 1
            key_2 = int_to_bytearray(int_value, self.block_size)
        else:
            int_value = bytearray_to_int(key_1) << 1
            key_2 = add_xor(int_to_bytearray(int_value, self.block_size), value_b)
        return [key_1, key_2]

    def _ecb_decrypt(self, data):
        #Decryption mode ECB
        if not self._pad_mode in (PAD_MODE_1, PAD_MODE_2):
            self.clear()
            raise ValueError('ValueError: unsupported padding mode')
        result = bytearray()
        for i in range(self._get_num_block(data)):
            result = (result + self._cipher_obj.decrypt(data[self.block_size *\
                      i:self.block_size + (self.block_size * i):]))
        return result

    def _cbc_decrypt(self, data):
        #Decryption mode CBC
        if not self._pad_mode in (PAD_MODE_1, PAD_MODE_2):
            self.clear()
            raise ValueError('ValueError: unsupported padding mode')
        if not self._init_vect or len(self._init_vect) < self.block_size\
                               or len(self._init_vect) % self.block_size != 0:
            self.clear()
            raise ValueError('ValueError: invalid initialization vector size')
        result = bytearray()
        for i in range(self._get_num_block(data)):
            cipher_blk = add_xor(\
                         self._init_vect[0:self.block_size], self._cipher_obj.decrypt(\
                         data[self.block_size * i:self.block_size + (self.block_size * i)]))
            result = result + cipher_blk
            self._init_vect[0:len(self._init_vect) - self.block_size] =\
                           self._init_vect[self.block_size:len(self._init_vect)]
            self._init_vect[len(self._init_vect) - self.block_size:len(self._init_vect)] =\
                           data[self.block_size * i:self.block_size + (self.block_size * i)]
        return result

    def _cfb_decrypt(self, data):
        #Decryption mode CFB
        if not self._init_vect or len(self._init_vect) < self.block_size\
                               or len(self._init_vect) % self.block_size != 0:
            self.clear()
            raise ValueError('ValueError: invalid initialization vector size')
        gamma = bytearray()
        result = bytearray()
        for i in range(self._get_num_block(data)):
            gamma = self._cipher_obj.encrypt(self._init_vect[0:self.block_size])
            cipher_blk = data[self.block_size * i:self.block_size + self.block_size * i]
            result = result + add_xor(gamma, cipher_blk)
            self._init_vect[0:len(self._init_vect) - self.block_size] =\
                           self._init_vect[self.block_size:len(self._init_vect)]
            self._init_vect[len(self._init_vect) - self.block_size:len(self._init_vect)] =\
                           cipher_blk
        if len(data) % self.block_size != 0:
            gamma = self._cipher_obj.encrypt(self._init_vect[0:self.block_size])
            cipher_blk = add_xor(gamma, data[self.block_size * self._get_num_block(data)::])
            result = result + cipher_blk
        return result

    def _ofb_decrypt(self, data):
        #Decryption mode OFB
        if not self._init_vect or len(self._init_vect) < self.block_size\
                               or len(self._init_vect) % self.block_size != 0:
            self.clear()
            raise ValueError('ValueError: invalid initialization vector size')
        gamma = bytearray()
        result = bytearray()
        for i in range(self._get_num_block(data)):
            gamma = self._cipher_obj.encrypt(self._init_vect[0:self.block_size])
            cipher_blk = add_xor(\
                         gamma, data[self.block_size * i:self.block_size + self.block_size * i])
            result = result + cipher_blk
            self._init_vect[0:len(self._init_vect) - self.block_size] =\
                           self._init_vect[self.block_size:len(self._init_vect)]
            self._init_vect[len(self._init_vect) - self.block_size:len(self._init_vect)] =\
                           gamma[0:self.block_size]
        if len(data) % self.block_size != 0:
            gamma = self._cipher_obj.encrypt(self._init_vect[0:self.block_size])
            cipher_blk = add_xor(gamma, data[self.block_size * self._get_num_block(data)::])
            result = result + cipher_blk
        return result

    def _ctr_decrypt(self, data):
        #Decryption mode CTR
        if not self._init_vect or len(self._init_vect) != self.block_size // 2:
            self.clear()
            raise ValueError('ValueError: invalid initialization vector size')
        gamma = bytearray()
        result = bytearray()
        for i in range(self._get_num_block(data)):
            gamma = self._cipher_obj.encrypt(self._counter)
            self._counter = self._inc_ctr(self._counter)
            result = result + add_xor(\
                     data[self.block_size * i:self.block_size + (self.block_size * i)], gamma)
        if len(data) % self.block_size != 0:
            gamma = self._cipher_obj.encrypt(self._counter)
            self._counter = self._inc_ctr(self._counter)
            result = result +\
                     add_xor(data[self.block_size * self._get_num_block(data)::], gamma)
        return result

    def _ecb_encrypt(self, data):
        #Encryption mode ECB
        if not self._pad_mode in (PAD_MODE_1, PAD_MODE_2):
            self.clear()
            raise ValueError('ValueError: unsupported padding mode')
        data = self._set_padding(data)
        result = bytearray()
        for i in range(self._get_num_block(data)):
            result = result + self._cipher_obj.encrypt(data[self.block_size *\
                     i:self.block_size + (self.block_size * i):1])
        return result

    def _cbc_encrypt(self, data):
        #Encryption mode CBC
        if not self._pad_mode in (PAD_MODE_1, PAD_MODE_2):
            self.clear()
            raise ValueError('ValueError: unsupported padding mode')
        if not self._init_vect or len(self._init_vect) < self.block_size\
                               or len(self._init_vect) % self.block_size != 0:
            self.clear()
            raise ValueError('ValueError: invalid initialization vector size')
        data = self._set_padding(data)
        result = bytearray()
        for i in range(self._get_num_block(data)):
            cipher_blk = self._cipher_obj.encrypt(add_xor(self._init_vect[0:self.block_size:],\
                         data[self.block_size * i:self.block_size + (self.block_size * i)]))
            result = result + cipher_blk
            self._init_vect[0:len(self._init_vect) - self.block_size] =\
                           self._init_vect[self.block_size:len(self._init_vect)]
            self._init_vect[len(self._init_vect) - self.block_size:len(self._init_vect)] =\
                           cipher_blk[0:self.block_size]
        return result

    def _cfb_encrypt(self, data):
        #Encryption mode CFB
        if not self._init_vect or len(self._init_vect) < self.block_size\
                               or len(self._init_vect) % self.block_size != 0:
            self.clear()
            raise ValueError('ValueError: invalid initialization vector size')
        gamma = bytearray()
        result = bytearray()
        for i in range(self._get_num_block(data)):
            gamma = self._cipher_obj.encrypt(self._init_vect[0:self.block_size])
            cipher_blk = add_xor(\
                         gamma, data[self.block_size * i:self.block_size + (self.block_size * i)])
            result = result + cipher_blk
            self._init_vect[0:len(self._init_vect) - self.block_size] =\
                           self._init_vect[self.block_size:len(self._init_vect)]
            self._init_vect[len(self._init_vect) - self.block_size:len(self._init_vect)] =\
                           cipher_blk[0:self.block_size]
        if len(data) % self.block_size != 0:
            gamma = self._cipher_obj.encrypt(self._init_vect[0:self.block_size])
            cipher_blk = add_xor(gamma, data[self.block_size * self._get_num_block(data)::])
            result = result + cipher_blk
        return result

    def _ofb_encrypt(self, data):
        #Encryption mode OFB
        if not self._init_vect or len(self._init_vect) < self.block_size\
                               or len(self._init_vect) % self.block_size != 0:
            self.clear()
            raise ValueError('ValueError: invalid initialization vector size')
        gamma = bytearray()
        result = bytearray()
        for i in range(self._get_num_block(data)):
            gamma = self._cipher_obj.encrypt(self._init_vect[0:self.block_size])
            cipher_blk = add_xor(\
                         gamma, data[self.block_size * i:self.block_size + (self.block_size * i)])
            result = result + cipher_blk
            self._init_vect[0:len(self._init_vect) - self.block_size] =\
                           self._init_vect[self.block_size:len(self._init_vect)]
            self._init_vect[len(self._init_vect) - self.block_size:len(self._init_vect)] =\
                           gamma[0:self.block_size]
        if len(data) % self.block_size != 0:
            gamma = self._cipher_obj.encrypt(self._init_vect[0:self.block_size])
            cipher_blk = add_xor(gamma, data[self.block_size * self._get_num_block(data)::])
            result = result + cipher_blk
        return result

    def _ctr_encrypt(self, data):
        #Encryption mode CTR
        if not self._init_vect or len(self._init_vect) != (self.block_size // 2):
            self.clear()
            raise ValueError('ValueError: 66invalid initialization vector size')
        gamma = bytearray()
        result = bytearray()
        for i in range(self._get_num_block(data)):
            gamma = self._cipher_obj.encrypt(self._counter)
            self._counter = self._inc_ctr(self._counter)
            result = result + add_xor(\
                     data[self.block_size * i:self.block_size + (self.block_size * i)], gamma)
        if len(data) % self.block_size != 0:
            gamma = self._cipher_obj.encrypt(self._counter)
            self._counter = self._inc_ctr(self._counter)
            result = result + add_xor(\
                     data[self.block_size * self._get_num_block(data)::], gamma)
        return result

    def decrypt(self, data):
        """Decrypting a ciphertext.

           Args:
             :data: Ciphertext data to be decrypted.

           Return:
              Plaintext data.

           Exception:
              ValueError('unsupported cipher mode') - in case of the unsupported cipher mode.
              ValueError('unsupported padding mode') - in case of the unsupported padding mode.
              ValueError('invalid initialization vector size') - in case of the
                 invalid initialization vector size.
        """
        if not self._mode in (MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR):
            self.clear()
            raise ValueError('ValueError: unsupported cipher mode')
        if self._mode == MODE_ECB:
            result = self._ecb_decrypt(data)
        elif self._mode == MODE_CBC:
            result = self._cbc_decrypt(data)
        elif self._mode == MODE_CFB:
            result = self._cfb_decrypt(data)
        elif self._mode == MODE_OFB:
            result = self._ofb_decrypt(data)
        elif self._mode == MODE_CTR:
            result = self._ctr_decrypt(data)
        return result

    def encrypt(self, data):
        """Encrypting a plaintext.

           Args:
             :data: Plaintext data to be encrypted.

           Return:
              Ciphertext data.

           Exception:
              ValueError('unsupported cipher mode') - in case of the unsupported cipher mode.
              ValueError('unsupported padding mode') - in case of the unsupported padding mode.
              ValueError('invalid initialization vector size') - in case of the
                 invalid initialization vector size.
        """
        if not self._mode in (MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, MODE_CTR):
            self.clear()
            raise ValueError('ValueError: unsupported cipher mode')
        if self._mode == MODE_ECB:
            result = self._ecb_encrypt(data)
        elif self._mode == MODE_CBC:
            result = self._cbc_encrypt(data)
        elif self._mode == MODE_CFB:
            result = self._cfb_encrypt(data)
        elif self._mode == MODE_OFB:
            result = self._ofb_encrypt(data)
        elif self._mode == MODE_CTR:
            result = self._ctr_encrypt(data)
        return result

    def update(self, data):
        """Update the MAC object with the bytes-like object.

           Args:
              :data: The string from which to get the MAC. Repeated calls are equivalent
                to a single call with the concatenation of all the arguments: m.update(a);
                m.update(b) is equivalent to m.update(a+b).
 
           Exception:
              ValueError('unsupported cipher mode') - in case of the unsupported cipher mode.
              ValueError('unsupported padding mode') - in case of the unsupported padding mode.
        """
        if self._mode != MODE_MAC:
            self.clear()
            raise ValueError('ValueError: unsupported cipher mode')
        if self._pad_mode != PAD_MODE_3:
            self.clear()
            raise ValueError('ValueError: unsupported padding mode')
        data = self._set_padding(data)
        block = bytearray()
        prev_block = self._cur_mac
        for i in range(0, self._get_num_block(data)-1):
            block = self._cipher_obj.encrypt(add_xor(\
                    prev_block, data[self.block_size * i:self.block_size + (self.block_size * i)]))
            prev_block = block
        block = self._cipher_obj.encrypt(add_xor(\
                prev_block, data[len(data) - self.block_size:len(data)]))
        self._cur_mac = block
        self._prev_mac = prev_block
        self._buff = data[self.block_size * (self._get_num_block(data) - 1):]

    def mac_final(self):
        """Return the final value of the MAC.
        """
        if self._mode != MODE_MAC:
            self.clear()
            raise ValueError('ValueError: unsupported cipher mode')
        if self._pad_mode != PAD_MODE_3:
            self.clear()
            raise ValueError('ValueError: unsupported padding mode')
        if self._get_pad_size(self._buff) == 0:
            final_key = self._key_1
        else:
            final_key = self._key_2
        self._buff = self._set_padding(self._buff)
        result = bytearray()
        result = self._cipher_obj.encrypt(add_xor(add_xor(\
                 self._prev_mac, self._buff), final_key))
        return result

    def digest(self, mac_size):
        """Calculating the Message authentication code (MAC).

           Args:
             :mac_size: Message authentication code size (in bytes).

           Return:
              Message authentication code value.

           Exception:
              ValueError('unsupported cipher mode') - in case of the unsupported cipher mode.
              ValueError('unsupported padding mode') - in case of the unsupported padding mode.
              ValueError('invalid message authentication code size') - in case of the invalid
                 message authentication code size.
        """
        temp = deepcopy(self)
        if mac_size > temp.block_size:
            temp.clear()
            raise ValueError('ValueError: invalid message authentication code size')
        return temp.mac_final()[0:mac_size:]

    def hexdigest(self, mac_size):
        """Calculating the Message authentication code of the data passed to the
             'update()' method so far an return it of the hexadecimal.

           Args:
             :mac_size: Message authentication code size (in bytes).

           Return:
              Message authentication code value in hexadecimal.

           Exception:
              ValueError('unsupported cipher mode') - in case of the unsupported cipher mode.
              ValueError('unsupported padding mode') - in case of the unsupported padding mode.
              ValueError('invalid message authentication code size') - in case of the invalid
                 message authentication code size
        """
        return self.digest(mac_size).hex()

    #pylint: disable=invalid-name
    @property
    def iv(self):
        """Contains the initial value which will be used to start a cipher feedback
           mode (CBC, CFB or OFB mode only).

           Exception:
              ValueError('invalid IV value') - in case of the invalid IV value.
        """
        if self._mode in (MODE_ECB, MODE_CTR):
            self.clear()
            raise ValueError('ValueError: invalid IV value')
        return self._init_vect[len(self._init_vect) - self.block_size::]
    #pylint: enable=invalid-name

    @property
    def counter(self):
        """Contains counter blocks (CTR mode only).

           Exception:
              ValueError('invalid counter value') - in case of the invalid counter value.
        """
        if self._mode != MODE_CTR:
            self.clear()
            raise ValueError('ValueError: invalid counter value')
        return self._counter

    @property
    def block_size(self):
        """An integer value the internal block size of the cipher algorithm in bytes.
           For the 'Kuznechik' algorithm this value is 16 and the 'Magma' algorithm,
           this value is 8.
        """
        return self._cipher_obj.block_size

    def clear(self):
        """Сlearing the values of iterative encryption keys.
        """
        if hasattr(self, '_cipher_obj'):
            self._cipher_obj.clear()
