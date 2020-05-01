#The GOST cryptographic functions.
#
#Author: Evgeny Drobotun (c) 2020
#License: MIT

"""
Block cipher modes according to GOST 34.13-2015.

The module implements the modes of operation of block encryption algorithms
"magma" and "kuznechik", described in GOST 34.13-2015.  The module includes
the base class GOST3413205, classes GOST3413205ecb, GOST3413205cbc,
GOST3413205cfb, GOST3413205ofb and GOST3413205ctr.  In addition the module
includes the GOSTCipherError class and several General functions.
"""

from copy import deepcopy

from typing import Any, Union

from gostcrypto.utils import add_xor
from gostcrypto.utils import int_to_bytearray
from gostcrypto.utils import bytearray_to_int
from gostcrypto.utils import zero_fill
from gostcrypto.utils import msb
from gostcrypto.utils import check_value

from .gost_34_12_2015 import GOST34122015Kuznechik
from .gost_34_12_2015 import GOST34122015Magma

MODE_ECB: int = 0x01  #Electronic Codebook mode
MODE_CBC: int = 0x02  #Cipher Block Chaining mode
MODE_CFB: int = 0x03  #Cipher Feedback mode
MODE_OFB: int = 0x05  #OutputFeedback mode
MODE_CTR: int = 0x06  #Counter mode
MODE_MAC: int = 0xff  #Message Authentication Code algorithm

PAD_MODE_1: int = 0x800000f0
PAD_MODE_2: int = 0x800000f1

_KEY_SIZE: int = 32

_DEFAULT_IV_CTR: bytearray = bytearray([
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0,
])

_DEFAULT_IV: bytearray = bytearray([
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0,
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
    0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
])

_B_64: bytearray = bytearray([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b,
])

_B_128: bytearray = bytearray([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
])

CipherObjType = Union[
    'GOST34132015',
    'GOST34132015ecb',
    'GOST34132015cbc',
    'GOST34132015cfb',
    'GOST34132015ofb',
    'GOST34132015ctr',
    'GOST34132015mac'
]


def get_num_block(data: bytearray, block_size: int) -> int:
    """Return the number of blocks in the data."""
    return len(data) // block_size


def get_pad_size(data: bytearray, block_size: int) -> int:
    """Return the padding size."""
    if len(data) < block_size:
        result = block_size - len(data)
    elif len(data) % block_size == 0:
        result = 0
    else:
        result = block_size - len(data) % block_size
    return result


def set_pad_mode_1(data: bytearray, block_size: int) -> bytearray:
    """
    Set padding MODE_PAD_1 mode.

    For MODE_ECB or MODE_CBC mode only.
    """
    return data + b'\x00' * get_pad_size(data, block_size)


def set_pad_mode_2(data: bytearray, block_size: int) -> bytearray:
    """
    Set padding MODE_PAD_2 mode.

    For MODE_ECB or MODE_CBC mode only.
    """
    return data + b'\x80' + b'\x00' * (block_size + get_pad_size(data, block_size) - 1)


def set_pad_mode_3(data: bytearray, block_size: int) -> bytearray:
    """
    Set padding MODE_PAD_3 mode.

    For MODE_MAC mode only.
    """
    if get_pad_size(data, block_size) == 0:
        result = data
    else:
        result = data + b'\x80' + b'\x00' * (get_pad_size(data, block_size) - 1)
    return result


def set_padding(data: bytearray, block_size: int, pad_mode: int) -> bytearray:
    """
    Select and set padding.

    For MODE_ECB or MODE_CBC mode only.
    """
    result = data
    if pad_mode == PAD_MODE_1:
        result = set_pad_mode_1(data, block_size)
    elif pad_mode == PAD_MODE_2:
        result = set_pad_mode_2(data, block_size)
    return result


def check_init_vect_value(init_vect: bytearray, block_size: int) -> bool:
    """
    Check the value of the initialization vector.

    It checks the type ('bytes' or 'bytearray') and matches the size (the size
    must be a multiple of the block size).  For MODE_CBC, MODE_CFB or MODE_OFB
    mode.
    """
    result = True
    if (not isinstance(init_vect, (bytes, bytearray))) or len(init_vect) % block_size != 0:
        result = False
    return result


def check_init_vect_value_ctr(init_vect: bytearray, block_size: int) -> bool:
    """
    Check the value of the initialization vector in MODE_CTR mode.

    It checks the type ('bytes' or 'bytearray') and matches the size (the size
    must be equal to half the block size).
    """
    result = True
    if (not isinstance(init_vect, (bytes, bytearray))) or len(init_vect) != block_size // 2:
        result = False
    return result


def new(algorithm: str, key: bytearray, mode: int, **kwargs) -> CipherObjType:
    """
    Create a new ciphering object and returns it.

    Args:
        - algorithm: the string with the name of the ciphering algorithm of the
    GOST R 34.12-201 ('kuznechik' with block size 128 bit or 'magma' with
    block size 64 bit).
        - key: byte object with 256-bit encryption key.
        - mode: mode of operation of the block encryption algorithm (valid value:
    MODE_CBC, MODE_CFB, MODE_CTR, MODE_ECB,MODE_OFB or MODE_MAC).

    Keyword args:
    - init_vect: byte object with initialization vector.  Used in MODE_CTR,
    MODE_OFB, MODE_CBC and MODE_CFB modes.  For MODE_CTR mode, the
    initialization vector length is equal to half the block size (default
    value iz '_DEFAULT_IV_CTR').  For MODE_CBC, MODE_OFB and MODE_CFB modes,
    it is a multiple of the block size (default value iz '_DEFAULT_IV').
    - data: the data from which to get the MAC (as a byte object).  For MODE_MAC
    mode only.  If this argument is passed to a function, you can immediately
    use the 'digest' (or 'hexdigest') method to calculate the MAC value after
    calling 'new'.  If the argument is not passed to the function, then you
    must use the 'update(data)' method before the 'digest' (or 'hexdigest')
    method.
    - pad_mode: padding mode for ECB or CBC (the default value is PAD_MODE_1).

    Return: new ciphering object.

    Raises:
    - GOSTCipherError('GOSTCipherError: unsupported cipher mode'): in case of
    unsupported cipher mode (is not MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB,
    MODE_CTR or MODE_MAC).
    - GOSTCipherError('GOSTCipherError: unsupported cipher algorithm'): in case
    of invalid value 'algorithm'.
    - GOSTCipherError('GOSTCipherError: invalid key value'): in case of invalid
    'key' value (the key value is not a byte object ('bytearray' or 'bytes') or
    its length is not 256 bits).
    - GOSTCipherError('GOSTCipherError: invalid padding mode'): in case padding
    mode is incorrect (for MODE_ECB and MODE_CBC modes).
    - GOSTCipherError('GOSTCipherError: invalid initialization vector value'):
    in case initialization vector value is incorrect (for all modes except ECB
    mode).
    - GOSTCipherError('GOSTCipherError: invalid text data'): in case where the
    text data is not byte object (for MODE_MAC mode).
    """
    result: Any = None
    if mode == MODE_ECB:
        pad_mode = kwargs.get('pad_mode', PAD_MODE_1)
        result = GOST34132015ecb(algorithm, key, pad_mode)
    elif mode == MODE_CBC:
        init_vect = kwargs.get('init_vect', _DEFAULT_IV)
        pad_mode = kwargs.get('pad_mode', PAD_MODE_1)
        result = GOST34132015cbc(algorithm, key, init_vect, pad_mode)
    elif mode == MODE_CFB:
        init_vect = kwargs.get('init_vect', _DEFAULT_IV)
        result = GOST34132015cfb(algorithm, key, init_vect)
    elif mode == MODE_OFB:
        init_vect = kwargs.get('init_vect', _DEFAULT_IV)
        result = GOST34132015ofb(algorithm, key, init_vect)
    elif mode == MODE_CTR:
        init_vect = kwargs.get('init_vect', _DEFAULT_IV_CTR)
        result = GOST34132015ctr(algorithm, key, init_vect)
    elif mode == MODE_MAC:
        data = kwargs.get('data', None)
        result = GOST34132015mac(algorithm, key, data)
    else:
        key = zero_fill(key)
        raise GOSTCipherError('GOSTCipherError: unsupported cipher mode')
    return result


class GOST34132015:
    """
    Base class of the cipher object.

    Methods
    - clear(): clearing the values of iterative cipher keys.

    Attributes
    - block_size: an integer value the internal block size of the cipher
    algorithm in bytes.
    """

    def __init__(self, algorithm: str, key: bytearray) -> None:
        """Initialize the ciphering object."""
        if algorithm not in ('magma', 'kuznechik'):
            key = zero_fill(key)
            raise GOSTCipherError('GOSTCipherError: unsupported cipher algorithm')
        if not check_value(key, _KEY_SIZE):
            key = zero_fill(key)
            raise GOSTCipherError('GOSTCipherError: invalid key value')
        if algorithm == 'kuznechik':
            self._cipher_obj = GOST34122015Kuznechik(key)
        elif algorithm == 'magma':
            self._cipher_obj = GOST34122015Magma(key)

    def __del__(self) -> None:
        """
        Delete the ciphering object.

        When deleting an instance of a class, it clears the values of
        iterative keys.
        """
        self.clear()

    def _get_block(self, data, count_block):
        return data[self.block_size * count_block:self.block_size + (self.block_size * count_block)]

    def clear(self) -> None:
        """Сlearing the values of iterative encryption keys."""
        if hasattr(self, '_cipher_obj'):
            self._cipher_obj.clear()

    @property
    def block_size(self) -> int:
        """
        Return the value of the internal block size of the cipher algorithm.

        For the 'kuznechik' algorithm this value is 16 and the 'magma'
        algorithm, this value is 8.
        """
        return self._cipher_obj.block_size


class GOST34132015Cipher(GOST34132015):
    """
    Base class of the cipher object for encryption modes.

    Methods
    - encrypt(): base method for encrypting plaintext.
    - decrypt(): base method for decrypting ciphertext.
    - clear(): clearing the values of iterative cipher keys.

    Attributes
    - block_size: an integer value the internal block size of the cipher
    algorithm in bytes.
    """

    def __init__(self, algorithm: str, key: bytearray) -> None:
        """Initialize the ciphering object."""
        super().__init__(algorithm, key)

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption (base method).

        Args
        - data: plaintext data to be encrypted (as a byte object).

        Return: an empty value of the bytearray type.

        Raises
        - GOSTCipherError('GOSTCipherError: invalid plaintext data'): in case
        where the plaintext data is not byte object.
        """
        if not isinstance(data, (bytes, bytearray)):
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid plaintext data')
        return bytearray()

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption (base method).

        Args
        - data: ciphertext data to be decrypted (as a byte object).

        Return: an empty value of the bytearray type.

        Raises
        - GOSTCipherError('GOSTCipherError: invalid ciphertext data'): in case
        where the ciphertext data is not byte object.
        """
        if not isinstance(data, (bytes, bytearray)):
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid ciphertext data')
        return bytearray()


class GOST34132015CipherPadding(GOST34132015Cipher):
    """
    Base class of the cipher object for encryption modes with padding.

    Methods
    - encrypt(): base method for encrypting plaintext.
    - decrypt(): base method for decrypting ciphertext.
    - clear(): clearing the values of iterative cipher keys.

    Attributes
    - block_size: an integer value the internal block size of the cipher
    algorithm in bytes.
    """

    def __init__(self, algorithm: str, key: bytearray, pad_mode: int) -> None:
        """Initialize the ciphering object."""
        GOST34132015Cipher.__init__(self, algorithm, key)
        if pad_mode not in (PAD_MODE_1, PAD_MODE_2):
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid padding mode')
        self._pad_mode = pad_mode

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption (base method).

        Args
        - data: plaintext data to be encrypted (as a byte object).

        Return: an empty value of the bytearray type.

        Raises
        - GOSTCipherError('GOSTCipherError: invalid plaintext data'): in case
        where the plaintext data is not byte object.
        """
        result = GOST34132015Cipher.encrypt(self, data)
        data = set_padding(data, self.block_size, self._pad_mode)
        return result, data

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption (base method).

        Args
        - data: ciphertext data to be decrypted (as a byte object).

        Return: an empty value of the bytearray type.

        Raises
        - GOSTCipherError('GOSTCipherError: invalid ciphertext data'): in case
        where the ciphertext data is not byte object.
        """
        result = GOST34132015Cipher.decrypt(self, data)
        return result


class GOST34132015CipherFeedBack(GOST34132015Cipher):
    """
    Base class of the cipher object for encryption modes with feedback.

    Methods
    - encrypt(): base method for encrypting plaintext.
    - decrypt(): base method for decrypting ciphertext.
    - clear(): clearing the values of iterative cipher keys.

    Attributes
    - block_size: an integer value the internal block size of the cipher
    algorithm in bytes.
    - iv: the initial value.
    """

    def __init__(self, algorithm: str, key: bytearray, init_vect: bytearray) -> None:
        """Initialize the ciphering object."""
        GOST34132015Cipher.__init__(self, algorithm, key)
        if not check_init_vect_value(init_vect, self.block_size):
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid initialization vector value')
        self._init_vect = init_vect
        self._init_vect = bytearray(self._init_vect)

    def _get_gamma(self) -> bytearray:
        return self._cipher_obj.encrypt(self._init_vect[0:self.block_size])

    def _set_init_vect(self, data: bytearray) -> bytearray:
        iter_iv_hi = self._init_vect[self.block_size:len(self._init_vect)]
        self._init_vect[0:len(self._init_vect) - self.block_size] = iter_iv_hi
        begin_iv_low = len(self._init_vect) - self.block_size
        end_iv_low = len(self._init_vect)
        self._init_vect[begin_iv_low:end_iv_low] = data

    def _get_final_block(self, data):
        return data[self.block_size * get_num_block(data, self.block_size)::]

    def _final_cipher(self, data):
        gamma = self._get_gamma()
        cipher_blk = self._get_final_block(data)
        return add_xor(gamma, cipher_blk)

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption (base method).

        Args
        - data: plaintext data to be encrypted (as a byte object).

        Return: an empty two value of the bytearray type.

        Raises
        - GOSTCipherError('GOSTCipherError: invalid plaintext data'): in case
        where the plaintext data is not byte object.
        """
        return GOST34132015Cipher.encrypt(self, data), bytearray()

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption (base method).

        Args
        - data: ciphertext data to be decrypted (as a byte object).

        Return: an empty value of the bytearray type.

        Raises
        - GOSTCipherError('GOSTCipherError: invalid ciphertext data'): in case
        where the ciphertext data is not byte object.
        """
        return GOST34132015Cipher.decrypt(self, data), bytearray()

    # pylint: disable=invalid-name
    @property
    def iv(self) -> bytearray:
        """Return the value of the initializing vector."""
        return self._init_vect[len(self._init_vect) - self.block_size::]
    # pylint: enable=invalid-name


class GOST34132015ecb(GOST34132015CipherPadding):
    """
    The class that implements ECB mode of block encryption.

    Methods
    - decrypt(): decrypting a ciphertext.
    - encrypt(): encrypting a plaintext.
    - clear(): clearing the values of iterative cipher keys.

    Attributes
    - block_size: an integer value the internal block size of the cipher
    algorithm in bytes.
    """

    def __init__(self, algorithm: str, key: bytearray, pad_mode: int) -> None:
        """Initialize the ciphering object in ECB mode."""
        super().__init__(algorithm, key, pad_mode)

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption in ECB mode.

        Args
        - data: plaintext data to be encrypted (as a byte object).

        Return: ciphertext data (as a byte object).

        Raises
        - GOSTCipherError('GOSTCipherError: invalid plaintext data'): in case
        where the plaintext data is not byte object.
        """
        result, data = super().encrypt(data)
        for i in range(get_num_block(data, self.block_size)):
            result = result + self._cipher_obj.encrypt(self._get_block(data, i))
        return result

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption in ECB mode.

        Args
        - data: ciphertext data to be decrypted (as a byte object).

        Return: plaintext data (as a byte object).

        Raises
        - GOSTCipherError('GOSTCipherError: invalid ciphertext data'): in case
        where the ciphertext data is not byte object.
        """
        result = super().decrypt(data)
        for i in range(get_num_block(data, self.block_size)):
            result = result + self._cipher_obj.decrypt(self._get_block(data, i))
        return result


class GOST34132015cbc(GOST34132015CipherPadding, GOST34132015CipherFeedBack):
    """
    The class that implements CBC mode of block encryption.

    Methods
    - decrypt(): decrypting a ciphertext.
    - encrypt(): encrypting a plaintext.
    - clear(): clearing the values of iterative cipher keys.

    Attributes
    - block_size: an integer value the internal block size of the cipher
    algorithm in bytes.
    - iv: the initial value.
    """

    def __init__(self, algorithm: str, key: bytearray,
                 init_vect: bytearray, pad_mode: int) -> None:
        """Initialize the ciphering object in CBC mode."""
        GOST34132015CipherPadding.__init__(self, algorithm, key, pad_mode)
        GOST34132015CipherFeedBack.__init__(self, algorithm, key, init_vect)

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption in CBC mode.

        Args
        - data: plaintext data to be encrypted (as a byte object).

        Return: ciphertext data (as a byte object).

        Raises
        - GOSTCipherError('GOSTCipherError: invalid plaintext data'): in case
        where the plaintext data is not byte object.
        """
        result, data = GOST34132015CipherPadding.encrypt(self, data)
        for i in range(get_num_block(data, self.block_size)):
            internal = add_xor(self._init_vect[0:self.block_size], self._get_block(data, i))
            cipher_blk = self._cipher_obj.encrypt(internal)
            result = result + cipher_blk
            self._set_init_vect(cipher_blk[0:self.block_size])
        return result

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption in CBC mode.

        Args
        - data: ciphertext data to be decrypted (as a byte object).

        Return: plaintext data (as a byte object).

        Raises
        - GOSTCipherError('GOSTCipherError: invalid ciphertext data'): in case
        where the ciphertext data is not byte object.
        """
        result = GOST34132015CipherPadding.decrypt(self, data)
        for i in range(get_num_block(data, self.block_size)):
            internal = self._cipher_obj.decrypt(self._get_block(data, i))
            cipher_blk = add_xor(self._init_vect[0:self.block_size], internal)
            result = result + cipher_blk
            self._set_init_vect(self._get_block(data, i))
        return result


class GOST34132015cfb(GOST34132015CipherFeedBack):
    """
    The class that implements CFB mode of block encryption.

    Methods
    - decrypt(): decrypting a ciphertext.
    - encrypt(): encrypting a plaintext.
    - clear(): clearing the values of iterative cipher keys.

    Attributes
    - block_size: an integer value the internal block size of the cipher
    algorithm in bytes.
    - iv: the initial value.
    """

    def __init__(self, algorithm: str, key: bytearray, init_vect: bytearray) -> None:
        """Initialize the ciphering object in CFB mode."""
        super().__init__(algorithm, key, init_vect)

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption in CFB mode.

        Args
        - data: plaintext data to be encrypted (as a byte object).

        Return: ciphertext data (as a byte object).

        Raises
        - GOSTCipherError('GOSTCipherError: invalid plaintext data'): in case
        where the plaintext data is not byte object.
        """
        result, gamma = super().encrypt(data)
        for i in range(get_num_block(data, self.block_size)):
            gamma = self._get_gamma()
            cipher_blk = add_xor(gamma, self._get_block(data, i))
            result = result + cipher_blk
            self._set_init_vect(cipher_blk[0:self.block_size])
        if len(data) % self.block_size != 0:
            result = result + self._final_cipher(data)
        return result

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption in CFB mode.

        Args
        - data: ciphertext data to be decrypted (as a byte object).

        Return: plaintext data (as a byte object).

        Raises
        - GOSTCipherError('GOSTCipherError: invalid ciphertext data'): in case
        where the ciphertext data is not byte object.
        """
        result, gamma = super().decrypt(data)
        for i in range(get_num_block(data, self.block_size)):
            gamma = self._get_gamma()
            cipher_blk = self._get_block(data, i)
            result = result + add_xor(gamma, cipher_blk)
            self._set_init_vect(cipher_blk)
        if len(data) % self.block_size != 0:
            result = result + self._final_cipher(data)
        return result


class GOST34132015ofb(GOST34132015CipherFeedBack):
    """
    The class that implements OFB mode of block encryption.

    Methods
    - decrypt(): decrypting a ciphertext.
    - encrypt(): encrypting a plaintext.
    - clear(): clearing the values of iterative cipher keys.

    Attributes
    - block_size: an integer value the internal block size of the cipher
    algorithm in bytes.
    - iv: the initial value.
    """

    def __init__(self, algorithm: str, key: bytearray, init_vect: bytearray) -> None:
        """Initialize the ciphering object in OFB mode."""
        super().__init__(algorithm, key, init_vect)

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption in OFB mode.

        Args
        :data: Plaintext data to be encrypted (as a byte object).

        Return:
        ciphertext data (as a byte object).

        Raises:
        - GOSTCipherError('GOSTCipherError: invalid plaintext data') - in case
        where the plaintext data is not byte object.
        """
        result, gamma = super().encrypt(data)
        for i in range(get_num_block(data, self.block_size)):
            gamma = self._get_gamma()
            cipher_blk = self._get_block(data, i)
            result = result + add_xor(gamma, cipher_blk)
            self._set_init_vect(gamma[0:self.block_size])
        if len(data) % self.block_size != 0:
            result = result + self._final_cipher(data)
        return result

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption in OFB mode.

        Args
        - data: ciphertext data to be decrypted (as a byte object).

        Return: plaintext data (as a byte object).

        Raises:
        - GOSTCipherError('GOSTCipherError: invalid plaintext data'): in case
        where the plaintext data is not byte object.
        """
        super().decrypt(data)
        return self.encrypt(data)

class GOST34132015ctr(GOST34132015Cipher):
    """
    The class that implements CTR mode of block encryption.

    Methods
    - decrypt(): decrypting a ciphertext.
    - encrypt(): encrypting a plaintext.
    - clear(): clearing the values of iterative cipher keys.

    Attributes
    - block_size: an integer value the internal block size of the cipher
    algorithm in bytes.
    - counter: counter blocks.
    """

    def __init__(self, algorithm: str, key: bytearray, init_vect: bytearray) -> None:
        """Initialize the ciphering object in CTR mode."""
        super().__init__(algorithm, key)
        if not check_init_vect_value_ctr(init_vect, self.block_size):
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid initialization vector value')
        self._init_vect = init_vect
        self._init_vect = bytearray(self._init_vect)
        self._counter = init_vect + b'\x00' * (self.block_size // 2)
        self._counter = bytearray(self._counter)

    def _inc_ctr(self, ctr: bytearray) -> bytearray:
        internal = 0
        bit = bytearray(self.block_size)
        bit[self.block_size - 1] = 0x01
        for i in range(self.block_size):
            internal = ctr[i] + bit[i] + (internal << 8)
            ctr[i] = internal & 0xff
        return ctr

    @property
    def counter(self) -> bytearray:
        """Return the value of the block counter."""
        return self._counter

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption in CTR mode.

        Args
        - data: plaintext data to be encrypted (as a byte object).

        Return: ciphertext data (as a byte object).

        Raises
        - GOSTCipherError('GOSTCipherError: invalid plaintext data'): in case
        where the plaintext data is not byte object.
        """
        result = super().encrypt(data)
        gamma = bytearray()
        for i in range(get_num_block(data, self.block_size)):
            gamma = self._cipher_obj.encrypt(self._counter)
            self._counter = self._inc_ctr(self._counter)
            result = result + add_xor(self._get_block(data, i), gamma)
        if len(data) % self.block_size != 0:
            gamma = self._cipher_obj.encrypt(self._counter)
            self._counter = self._inc_ctr(self._counter)
            result = result + add_xor(
                data[self.block_size * get_num_block(data, self.block_size)::], gamma
            )
        return result

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption in CTR mode.

        Args
        - data: ciphertext data to be decrypted (as a byte object).

        Return: plaintext data (as a byte object).

        Raises
        - GOSTCipherError('GOSTCipherError: invalid ciphertext data'): in case
        where the ciphertext data is not byte object.
        """
        super().decrypt(data)
        return self.encrypt(data)


class GOST34132015mac(GOST34132015):
    """
    The class that implements MAC mode.

    Methods
    - update(): update the MAC object with the bytes-like object.
    - digest(): calculating the Message authentication code of the data passed
    to the 'update()' method so far.
    - hexdigest(): calculating the Message authentication code of the data
    passed to the 'update()' method so far an return it of the hexadecimal.
    - clear(): clearing the values of iterative cipher keys.

    Attributes
    - block_size: an integer value the internal block size of the cipher
    algorithm in bytes.
    """

    def __init__(self, algorithm: str, key: bytearray, data: bytearray) -> None:
        """Initialize the ciphering object in MAC mode."""
        super().__init__(algorithm, key)
        value_r = self._cipher_obj.encrypt(bytearray(self._cipher_obj.block_size * b'\x00'))
        self._key_1, self._key_2 = self._get_mac_key(value_r)
        self._buff = bytearray(self._cipher_obj.block_size)
        self._prev_mac = bytearray(self._cipher_obj.block_size)
        self._cur_mac = bytearray(self._cipher_obj.block_size)
        if data is not None:
            self.update(data)

    def _get_mac_key(self, value_r):
        value_b = b''
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

    def update(self, data: bytearray) -> None:
        """
        Update the MAC object with the bytes-like object.

        Args
        - data: The data from which to get the MAC (as a byte object).  Repeated
        calls are equivalent to a single call with the concatenation of all the
        arguments: 'm.update(a)'; 'm.update(b)' is equivalent to
        'm.update(a+b)'.

        Raises
        - GOSTCipherError('GOSTCipherError: invalid text data'): in case where
        the text data is not byte object.
        """
        if not isinstance(data, (bytes, bytearray)):
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid text data')
        data = set_pad_mode_3(data, self.block_size)
        block = bytearray()
        prev_block = self._cur_mac
        for i in range(0, get_num_block(data, self.block_size) - 1):
            block = self._cipher_obj.encrypt(add_xor(prev_block, self._get_block(data, i)))
            prev_block = block
        block = (
            self._cipher_obj.encrypt(
                add_xor(prev_block, data[len(data) - self.block_size:len(data)])
            )
        )
        self._cur_mac = block
        self._prev_mac = prev_block
        self._buff = data[self.block_size * (get_num_block(data, self.block_size) - 1):]

    def mac_final(self) -> bytearray:
        """Return the final value of the MAC."""
        if get_pad_size(self._buff, self.block_size) == 0:
            final_key = self._key_1
        else:
            final_key = self._key_2
        self._buff = set_pad_mode_3(self._buff, self.block_size)
        result = bytearray()
        result = self._cipher_obj.encrypt(
            add_xor(add_xor(self._prev_mac, self._buff), final_key)
        )
        return result

    def digest(self, mac_size: int) -> bytearray:
        """
        Calculate the Message authentication code (MAC).

        This method can be called after applying the 'update ()' method, or
        after calling the 'new ()' function with the data passed to it for MAC
        calculation.

        Args
        - mac_size: message authentication code size (in bytes).

        Return: message authentication code value (as a byte object).

        Raises:
        - GOSTCipherError('GOSTCipherError: invalid message authentication code
        size'): in case of the invalid message authentication code size.
        """
        temp = deepcopy(self)
        if mac_size > temp.block_size:
            temp.clear()
            raise GOSTCipherError('GOSTCipherError: invalid message authentication code size')
        return temp.mac_final()[0:mac_size:]

    def hexdigest(self, mac_size: int) -> str:
        """
        Calculate the Message authentication code (MAC).

        This method can be called after applying the 'update ()' method, or
        after calling the 'new ()' function with the data passed to it for MAC
        calculation.  The result is represented as a hexadecimal string.

        Args
        - mac_size: message authentication code size (in bytes).

        Return: message authentication code value in hexadecimal (as a
        hexadecimal string).

        Raises
        - GOSTCipherError('GOSTCipherError: invalid message authentication code
        size'): in case of the invalid message authentication code size.
        """
        return self.digest(mac_size).hex()


class GOSTCipherError(Exception):
    """
    The class that implements exceptions.

    Exceptions
    - unsupported cipher mode.
    - unsupported cipher algorithm.
    - invalid key value.
    - invalid padding mode.
    - invalid initialization vector value.
    - invalid text data.
    - invalid plaintext data.
    - invalid ciphertext data.
    - invalid message authentication code size.
    """
