# pylint: disable=duplicate-code
# pylint: disable=too-many-lines

#The GOST cryptographic functions.
#
#Author: Evgeny Drobotun (c) 2020
#License: MIT

"""
Block cipher modes according to GOST 34.13-2015.

The module implements the modes of operation of block encryption algorithms
"magma" and "kuznechik", described in GOST 34.13-2015.  The module includes
the base classes 'GOST3413205', 'GOST3413205Cipher', 'GOST3413205CipherPadding',
'GOST3413205CipherFeedBack', and classes 'GOST3413205ecb', 'GOST3413205cbc',
'GOST3413205cfb', 'GOST3413205ofb' and 'GOST3413205ctr'.  In addition the module
includes the GOSTCipherError class and several general functions.

Attributes:
    MODE_ECB: Electronic Codebook mode.
    MODE_CBC: Cipher Block Chaining mode.
    MODE_CFB: Cipher Feedback mode.
    MODE_OFB: OutputFeedback mode.
    MODE_CTR: Counter mode.
    MODE_MAC: Message Authentication Code algorithm.
    PAD_MODE_1: Message padding procedure No. 1 (paragraph 4.1.1
      GOST 34.13-2015)
    PAD_MODE_2: Message padding procedure No. 2 (paragraph 4.1.2
      GOST 34.13-2015)
"""
# pylint: enable=duplicate-code

from copy import deepcopy
from typing import Any, Union
from abc import ABC, abstractmethod

from gostcrypto.utils import add_xor
from gostcrypto.utils import int_to_bytearray
from gostcrypto.utils import bytearray_to_int
from gostcrypto.utils import zero_fill
from gostcrypto.utils import msb
from gostcrypto.utils import check_value

from .gost_34_12_2015 import GOST34122015Kuznechik
from .gost_34_12_2015 import GOST34122015Magma

MODE_ECB: int = 0x01
MODE_CBC: int = 0x02
MODE_CFB: int = 0x03
MODE_OFB: int = 0x05
MODE_CTR: int = 0x06
MODE_MAC: int = 0xff

PAD_MODE_1: int = 0x800000f0
PAD_MODE_2: int = 0x800000f1

_KEY_SIZE: int = 32

_DEFAULT_IV_CTR_KUZNECHIK: bytearray = bytearray([
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0,
])

_DEFAULT_IV_CTR_MAGMA: bytearray = bytearray([
    0x12, 0x34, 0x56, 0x78,
])

_DEFAULT_IV_KUZNECHIK: bytearray = bytearray([
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0,
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
    0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
])

_DEFAULT_IV_MAGMA: bytearray = bytearray([
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1,
])

_DEFAULT_IV_CBC_MAGMA: bytearray = bytearray([
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1,
    0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12,
])

_B_64: bytearray = bytearray([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b,
])

_B_128: bytearray = bytearray([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
])

CipherType = Union[
    'GOST34132015ecb',
    'GOST34132015cbc',
    'GOST34132015cfb',
    'GOST34132015ofb',
    'GOST34132015ctr',
    'GOST34132015mac'
]

CipherObjType = Union[
    'GOST34122015Kuznechik',
    'GOST34122015Magma',
]


def new(algorithm: str, key: bytearray, mode: int, **kwargs) -> CipherType:
    """
    Create a new ciphering object and returns it.

    Args:
        algorithm: The string with the name of the ciphering algorithm of the
          GOST R 34.12-2015 ('kuznechik' with block size 128 bit or 'magma' with
          block size 64 bit).
        key: Byte object with 256-bit encryption key.
        mode: Mode of operation of the block encryption algorithm (valid value:
          MODE_CBC, MODE_CFB, MODE_CTR, MODE_ECB,MODE_OFB or MODE_MAC).
        **init_vect: Byte object with initialization vector.  Used in MODE_CTR,
          MODE_OFB, MODE_CBC and MODE_CFB modes.  For MODE_CTR mode, the
          initialization vector length is equal to half the block size (default
          value iz '_DEFAULT_IV_CTR').  For MODE_CBC, MODE_OFB and MODE_CFB
          modes, it is a multiple of the block size (default value is
          '_DEFAULT_IV').
        **data: The data from which to get the MAC (as a byte object).  For
          MODE_MAC mode only.  If this argument is passed to a function, you
          can immediately use the 'digest' (or 'hexdigest') method to calculate
          the MAC value after calling 'new'.  If the argument is not passed to
          the function, then you must use the 'update(data)' method before the
          'digest' (or 'hexdigest') method.
        **pad_mode: Padding mode for ECB or CBC (the default value is
          PAD_MODE_1).

    Returns:
        New ciphering object.

    Raises:
        GOSTCipherError('GOSTCipherError: unsupported cipher mode'): In case
          of unsupported cipher mode (is not MODE_ECB, MODE_CBC, MODE_CFB,
          MODE_OFB, MODE_CTR or MODE_MAC).
        GOSTCipherError('GOSTCipherError: unsupported cipher algorithm'): In
          case of invalid value 'algorithm'.
        GOSTCipherError('GOSTCipherError: invalid key value'): In case of
          invalid 'key' value (the key value is not a byte object ('bytearray'
          or 'bytes') or its length is not 256 bits).
        GOSTCipherError('GOSTCipherError: invalid padding mode'): In case
          padding mode is incorrect (for MODE_ECB and MODE_CBC modes).
        GOSTCipherError('GOSTCipherError: invalid initialization vector
          value'): In case initialization vector value is incorrect (for all
          modes except ECB mode).
        GOSTCipherError('GOSTCipherError: invalid text data'): In case where
          the text data is not byte object (for MODE_MAC mode).
    """
    result: Any = None
    if mode == MODE_ECB:
        pad_mode = kwargs.get('pad_mode', PAD_MODE_1)
        result = GOST34132015ecb(algorithm, key, pad_mode)
    elif mode == MODE_CBC:
        init_vect = kwargs.get('init_vect', _DEFAULT_IV_KUZNECHIK)
        if algorithm == 'magma':
            init_vect = kwargs.get('init_vect', _DEFAULT_IV_CBC_MAGMA)
        pad_mode = kwargs.get('pad_mode', PAD_MODE_1)
        result = GOST34132015cbc(algorithm, key, init_vect, pad_mode)
    elif mode == MODE_CFB:
        init_vect = kwargs.get('init_vect', _DEFAULT_IV_KUZNECHIK)
        if algorithm == 'magma':
            init_vect = kwargs.get('init_vect', _DEFAULT_IV_MAGMA)
        result = GOST34132015cfb(algorithm, key, init_vect)
    elif mode == MODE_OFB:
        init_vect = kwargs.get('init_vect', _DEFAULT_IV_KUZNECHIK)
        if algorithm == 'magma':
            init_vect = kwargs.get('init_vect', _DEFAULT_IV_MAGMA)
        result = GOST34132015ofb(algorithm, key, init_vect)
    elif mode == MODE_CTR:
        init_vect = kwargs.get('init_vect', _DEFAULT_IV_CTR_KUZNECHIK)
        if algorithm == 'magma':
            init_vect = kwargs.get('init_vect', _DEFAULT_IV_CTR_MAGMA)
        result = GOST34132015ctr(algorithm, key, init_vect)
    elif mode == MODE_MAC:
        data = kwargs.get('data', bytearray(b''))
        result = GOST34132015mac(algorithm, key, data)
    else:
        key = zero_fill(key)
        raise GOSTCipherError('GOSTCipherError: unsupported cipher mode')
    return result


class GOST34132015(ABC):
    """
    Base class of the cipher object.

    This class is a superclass for the 'GOST34132015Cipher' and
    'GOST34132015mac' classes.

    Methods:
        clear(): Clearing the values of iterative cipher keys.

    Attributes:
        block_size: An integer value the internal block size of the cipher
          algorithm in bytes.
        oid: String  with the dotted representation of the object identifier
          respective to the encryption algorithm.
        oid.name: String  with name of the object identifier respective to the
          encryption algorithm.
        oid.digit: The object identifier respective to the encryption algorithm
          as a tuple of integers.
        oid.octet: The object identifier respective to the encryption algorithm
          as a byte object encoded ASN.1.
    """

    def __init__(self, algorithm: str, key: bytearray) -> None:
        """
        Initialize the ciphering object.

        Args:
            algorithm: The string with the name of the ciphering algorithm.
            key: The encryption key.

        Raises:
            GOSTCipherError('GOSTCipherError: unsupported cipher algorithm'): In
              case of unsupported cipher algorithm (is not 'kuznechik' or
              'magma').
            GOSTCipherError('GOSTCipherError: invalid key value'): In case of
              invalid 'key' value (the key value is not a byte object
              ('bytearray' or 'bytes') or its length is not 256 bits).
        """
        if algorithm not in ('magma', 'kuznechik'):
            key = zero_fill(key)
            raise GOSTCipherError('GOSTCipherError: unsupported cipher algorithm')
        if not check_value(key, _KEY_SIZE):
            key = zero_fill(key)
            raise GOSTCipherError('GOSTCipherError: invalid key value')
        if algorithm == 'kuznechik':
            self._cipher_obj: CipherObjType = GOST34122015Kuznechik(key)
        elif algorithm == 'magma':
            self._cipher_obj : CipherObjType = GOST34122015Magma(key)
        self.oid = self._cipher_obj.oid

    def __del__(self) -> None:
        """
        Delete the ciphering object.

        When deleting an instance of a class, it clears the values of
        iterative keys.
        """
        self.clear()

    def _get_num_block(self, data: bytearray) -> int:
        return len(data) // self.block_size

    def _get_pad_size(self, data: bytearray) -> int:
        if len(data) < self.block_size:
            result = self.block_size - len(data)
        elif len(data) % self.block_size == 0:
            result = 0
        else:
            result = self.block_size - len(data) % self.block_size
        return result

    def _get_block(self, data: bytearray, count_block: int) -> bytearray:
        begin_block = self.block_size * count_block
        end_block = self.block_size + (self.block_size * count_block)
        return data[begin_block:end_block]

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


class GOST34132015Cipher(GOST34132015, ABC):
    """
    Base class of the cipher object for implementing encryption modes.

    This class is the subclass of the 'GOST3413205' class and inherits the
    'clear()' method and the 'block_size' attribute.  Class 'GOST34132015Cipher'
    is a superclass for the `'GOST34132015CipherPadding',
    'GOST34132015CipherFeedBack' and 'GOST34132015ctr' classes.

    Methods:
        encrypt(): Encrypting plaintext (abstract method).
        decrypt(): Decrypting ciphertext (abstract method).
        clear(): Clearing the values of iterative cipher keys.

    Attributes:
        block_size: An integer value the internal block size of the cipher
          algorithm in bytes.
    """

    @abstractmethod
    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption (abstract method).

        Args:
            data: Plaintext data to be encrypted (as a byte object).

        Returns:
            An empty value of the bytearray type.

        Raises:
            GOSTCipherError('GOSTCipherError: invalid plaintext data'): In
              case where the plaintext data is not byte object.
        """
        if not isinstance(data, (bytes, bytearray)):
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid plaintext data')
        return data

    @abstractmethod
    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption (abstract method).

        Args:
            data: Ciphertext data to be decrypted (as a byte object).

        Returns:
            An empty value of the bytearray type.

        Raises:
            GOSTCipherError('GOSTCipherError: invalid ciphertext data'): In
              case where the ciphertext data is not byte object.
        """
        if not isinstance(data, (bytes, bytearray)):
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid ciphertext data')
        return data


class GOST34132015CipherPadding(GOST34132015Cipher, ABC):
    """
    Base class of the cipher object with padding.

    This class is the subclass of the 'GOST3413205Cipher' class and inherits
    the 'clear()' method and the 'block_size' attribute.  The 'encrypt()' and
    'decrypt()' methods are redefined. Class 'GOST34132015CipherPadding' is a
    superclass for the 'GOST34132015ecb' and 'GOST34132015cbc' classes.

    Methods:
        encrypt(): Encrypting plaintext (abstract method).
        decrypt(): Decrypting ciphertext (abstract method).
        clear(): Clearing the values of iterative cipher keys.

    Attributes:
        block_size: An integer value the internal block size of the cipher
          algorithm in bytes.
    """

    def __init__(self, algorithm: str, key: bytearray, pad_mode: int) -> None:
        """
        Initialize the ciphering object.

        Args:
            algorithm: The string with the name of the ciphering algorithm.
            key: Encryption key.
            pad_mode: Padding mode value.
        """
        GOST34132015Cipher.__init__(self, algorithm, key)
        if pad_mode not in (PAD_MODE_1, PAD_MODE_2):
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid padding mode')
        self._pad_mode = pad_mode

    def _set_pad_mode_1(self, data: bytearray) -> bytearray:
        return data + b'\x00' * self._get_pad_size(data)

    def _set_pad_mode_2(self, data: bytearray) -> bytearray:
        return data + b'\x80' + b'\x00' * (self.block_size + self._get_pad_size(data) - 1)

    def _set_padding(self, data: bytearray, pad_mode: int) -> bytearray:
        result = data
        if pad_mode == PAD_MODE_1:
            result = self._set_pad_mode_1(data)
        elif pad_mode == PAD_MODE_2:
            result = self._set_pad_mode_2(data)
        return result

    @abstractmethod
    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption (abstract method).

        Args:
            data: Plaintext data to be encrypted (as a byte object).

        Returns:
            An empty value of the bytearray type.

        Raises:
            GOSTCipherError('GOSTCipherError: invalid plaintext data'): In
              case where the plaintext data is not byte object.
        """
        data = self._set_padding(GOST34132015Cipher.encrypt(self, data), self._pad_mode)
        return data

    @abstractmethod
    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption (abstract method).

        Args:
            data: Ciphertext data to be decrypted (as a byte object).

        Returns:
            An empty value of the bytearray type.

        Raises:
            GOSTCipherError('GOSTCipherError: invalid ciphertext data'): In
              case where the ciphertext data is not byte object.
        """
        data = GOST34132015Cipher.decrypt(self, data)
        return data


class GOST34132015CipherFeedBack(GOST34132015Cipher, ABC):
    """
    Base class of the cipher object with feedback.

    This class is the subclass of the 'GOST3413205Cipher' class and inherits
    the 'clear()' method and the 'block_size' attribute.  The 'encrypt()' and
    'decrypt()' methods are redefined. Class 'GOST34132015CipherFeedBack' is
    a superclass for the 'GOST34132015cbc', 'GOST34132015cfb' and
    'GOST34132015ofb' classes.

    Methods:
        encrypt(): Encrypting plaintext (abstract method).
        decrypt(): Decrypting ciphertext (abstract method).
        clear(): Clearing the values of iterative cipher keys.

    Attributes:
        block_size: An integer value the internal block size of the cipher
          algorithm in bytes.
        iv: The initial vector value.
    """

    def __init__(self, algorithm: str, key: bytearray, init_vect: bytearray) -> None:
        """
        Initialize the ciphering object.

        Args:
            algorithm: The string with the name of the ciphering algorithm.
            key: Encryption key.
            init_vect: Initialization vector value.
        """
        GOST34132015Cipher.__init__(self, algorithm, key)
        check_init_vect = isinstance(init_vect, (bytes, bytearray))
        if (not check_init_vect) or (len(init_vect) % self.block_size) != 0:
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid initialization vector value')
        self._init_vect = init_vect
        self._init_vect = bytearray(self._init_vect)

    def _get_gamma(self) -> bytearray:
        return self._cipher_obj.encrypt(self._init_vect[0:self.block_size])

    def _set_init_vect(self, data: bytearray):
        iter_iv_hi = self._init_vect[self.block_size:len(self._init_vect)]
        self._init_vect[0:len(self._init_vect) - self.block_size] = iter_iv_hi
        begin_iv_low = len(self._init_vect) - self.block_size
        end_iv_low = len(self._init_vect)
        self._init_vect[begin_iv_low:end_iv_low] = data

    def _get_final_block(self, data):
        return data[self.block_size * self._get_num_block(data)::]

    def _final_cipher(self, data):
        gamma = self._get_gamma()
        cipher_block = self._get_final_block(data)
        return add_xor(gamma, cipher_block)

    @abstractmethod
    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption ((abstract method)).

        Args:
            data: Plaintext data to be encrypted (as a byte object).

        Returns:
            An empty two value of the bytearray type.

        Raises:
            GOSTCipherError('GOSTCipherError: invalid plaintext data'): In
              case where the plaintext data is not byte object.
        """
        data = GOST34132015Cipher.encrypt(self, data)
        return data

    @abstractmethod
    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption ((abstract method)).

        Args:
            data: Ciphertext data to be decrypted (as a byte object).

        Returns:
            An empty value of the bytearray type.

        Raises:
            GOSTCipherError('GOSTCipherError: invalid ciphertext data'): In
              case where the ciphertext data is not byte object.
        """
        data = GOST34132015Cipher.decrypt(self, data)
        return data

    # pylint: disable=invalid-name
    @property
    def iv(self) -> bytearray:
        """Return the value of the initializing vector."""
        return self._init_vect[len(self._init_vect) - self.block_size::]
    # pylint: enable=invalid-name


class GOST34132015ecb(GOST34132015CipherPadding):
    """
    Class that implements ECB mode of block encryption.

    This class is the subclass of the 'GOST3413205CipherPadding' class and
    inherits the 'clear()' method and the 'block_size' attribute.  The
    'encrypt()' and 'decrypt()' methods are redefined.

    Methods:
        decrypt(): Decrypting a ciphertext.
        encrypt(): Encrypting a plaintext.
        clear(): Clearing the values of iterative cipher keys.

    Attributes:
        block_size: An integer value the internal block size of the cipher
          algorithm in bytes.
    """

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption in ECB mode.

        Args:
            data: Plaintext data to be encrypted (as a byte object).

        Returns:
            Ciphertext data (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid plaintext data'): In
              case where the plaintext data is not byte object.
        """
        result = bytearray()
        data = super().encrypt(data)
        for i in range(self._get_num_block(data)):
            result = result + self._cipher_obj.encrypt(self._get_block(data, i))
        return result

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption in ECB mode.

        Args:
            data: Ciphertext data to be decrypted (as a byte object).

        Returns:
            Plaintext data (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid ciphertext data'): In
              case where the ciphertext data is not byte object.
        """
        result = bytearray()
        data = super().decrypt(data)
        for i in range(self._get_num_block(data)):
            result = result + self._cipher_obj.decrypt(self._get_block(data, i))
        return result


class GOST34132015cbc(GOST34132015CipherPadding, GOST34132015CipherFeedBack):
    """
    Class that implements CBC mode of block encryption.

    This class is the subclass of the 'GOST3413205CipherPadding' and
    'GOST34132015CipherFeedBack' classes and inherits the 'clear()' method and
    the 'block_size' and 'iv' attributes.  The 'encrypt()' and 'decrypt()'
    methods are redefined.

    Methods:
        decrypt(): Decrypting a ciphertext.
        encrypt(): Encrypting a plaintext.
        clear(): Clearing the values of iterative cipher keys.

    Attributes:
        block_size: An integer value the internal block size of the cipher
          algorithm in bytes.
        iv: The initial vector value.
    """

    def __init__(self, algorithm: str, key: bytearray,
                 init_vect: bytearray, pad_mode: int) -> None:
        """
        Initialize the ciphering object in CBC mode.

        Args:
            algorithm: The string with the name of the ciphering algorithm.
            key: Encryption key.
            init_vect: Initialization vector value.
            pad_mode: Padding mode value.
        """
        GOST34132015CipherPadding.__init__(self, algorithm, key, pad_mode)
        GOST34132015CipherFeedBack.__init__(self, algorithm, key, init_vect)

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption in CBC mode.

        Args:
            data: Plaintext data to be encrypted (as a byte object).

        Returns:
            Ciphertext data (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid plaintext data'): In
              case where the plaintext data is not byte object.
        """
        result = bytearray()
        data = GOST34132015CipherPadding.encrypt(self, data)
        for i in range(self._get_num_block(data)):
            internal = add_xor(self._init_vect[0:self.block_size], self._get_block(data, i))
            cipher_block = self._cipher_obj.encrypt(internal)
            result = result + cipher_block
            self._set_init_vect(cipher_block[0:self.block_size])
        return result

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption in CBC mode.

        Args:
            data: Ciphertext data to be decrypted (as a byte object).

        Returns:
            Plaintext data (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid ciphertext data'): In
              case where the ciphertext data is not byte object.
        """
        result = bytearray()
        data = GOST34132015CipherPadding.decrypt(self, data)
        for i in range(self._get_num_block(data)):
            internal = self._cipher_obj.decrypt(self._get_block(data, i))
            cipher_block = add_xor(self._init_vect[0:self.block_size], internal)
            result = result + cipher_block
            self._set_init_vect(self._get_block(data, i))
        return result


class GOST34132015cfb(GOST34132015CipherFeedBack):
    """
    Class that implements CFB mode of block encryption.

    This class is the subclass of the 'GOST34132015CipherFeedBack' class and
    inherits the 'clear()' method and the 'block_size' and 'iv' attributes.
    The 'encrypt()' and 'decrypt()' methods are redefined.

    Methods:
        decrypt(): Decrypting a ciphertext.
        encrypt(): Encrypting a plaintext.
        clear(): Clearing the values of iterative cipher keys.

    Attributes:
        block_size: An integer value the internal block size of the cipher
          algorithm in bytes.
        iv: The initial vector value.
    """

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption in CFB mode.

        Args:
            data: Plaintext data to be encrypted (as a byte object).

        Returns:
            Ciphertext data (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid plaintext data'): In
              case where the plaintext data is not byte object.
        """
        result = bytearray()
        gamma = bytearray()
        data = super().encrypt(data)
        for i in range(self._get_num_block(data)):
            gamma = self._get_gamma()
            cipher_block = add_xor(gamma, self._get_block(data, i))
            result = result + cipher_block
            self._set_init_vect(cipher_block[0:self.block_size])
        if len(data) % self.block_size != 0:
            result = result + self._final_cipher(data)
        return result

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption in CFB mode.

        Args:
            data: Ciphertext data to be decrypted (as a byte object).

        Returns:
            Plaintext data (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid ciphertext data'): In
              case where the ciphertext data is not byte object.
        """
        result = bytearray()
        gamma = bytearray()
        data = super().decrypt(data)
        for i in range(self._get_num_block(data)):
            gamma = self._get_gamma()
            cipher_block = self._get_block(data, i)
            result = result + add_xor(gamma, cipher_block)
            self._set_init_vect(cipher_block)
        if len(data) % self.block_size != 0:
            result = result + self._final_cipher(data)
        return result


class GOST34132015ofb(GOST34132015CipherFeedBack):
    """
    Class that implements OFB mode of block encryption.

    This class is the subclass of the 'GOST34132015CipherFeedBack' class and
    inherits the 'clear()' method and the 'block_size' and 'iv' attributes.
    The 'encrypt()' and 'decrypt()' methods are redefined.

    Methods:
        decrypt(): Decrypting a ciphertext.
        encrypt(): Encrypting a plaintext.
        clear(): Clearing the values of iterative cipher keys.

    Attributes:
        block_size: An integer value the internal block size of the cipher
          algorithm in bytes.
        iv: The initial vector value.
    """

    def encrypt(self, data: bytearray) -> bytearray:
        """
        Plaintext encryption in OFB mode.

        Args:
            data: Plaintext data to be encrypted (as a byte object).

        Returns:
            Ciphertext data (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid plaintext data'): In
              case where the plaintext data is not byte object.
        """
        result = bytearray()
        gamma = bytearray()
        data = super().encrypt(data)
        for i in range(self._get_num_block(data)):
            gamma = self._get_gamma()
            cipher_block = self._get_block(data, i)
            result = result + add_xor(gamma, cipher_block)
            self._set_init_vect(gamma[0:self.block_size])
        if len(data) % self.block_size != 0:
            result = result + self._final_cipher(data)
        return result

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption in OFB mode.

        Args:
            data: Ciphertext data to be decrypted (as a byte object).

        Returns:
            Plaintext data (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid plaintext data'): In
              case where the plaintext data is not byte object.
        """
        super().decrypt(data)
        return self.encrypt(data)


class GOST34132015ctr(GOST34132015Cipher):
    """
    Class that implements CTR mode of block encryption.

    This class is the subclass of the 'GOST3413205Cipher' class and inherits
    the 'clear()' method and the 'block_size' attribute.  The 'encrypt()' and
    'decrypt()' methods are redefined.

    Methods:
        decrypt(): Decrypting a ciphertext.
        encrypt(): Encrypting a plaintext.
        clear(): Clearing the values of iterative cipher keys.

    Attributes:
        block_size: An integer value the internal block size of the cipher
          algorithm in bytes.
        counter: The counter block value.
    """

    def __init__(self, algorithm: str, key: bytearray,
                 init_vect: bytearray) -> None:
        """
        Initialize the ciphering object in CTR mode.

        Args:
            algorithm: The string with the name of the ciphering algorithm.
            key: Encryption key.
            init_vect: Initialization vector value.
        """
        super().__init__(algorithm, key)
        check_init_vect = isinstance(init_vect, (bytes, bytearray))
        if (not check_init_vect) or len(init_vect) != self.block_size // 2:
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

        Args:
            data: Plaintext data to be encrypted (as a byte object).

        Returns:
            Ciphertext data (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid plaintext data'): In
              case where the plaintext data is not byte object.
        """
        result = bytearray()
        gamma = bytearray()
        data = super().encrypt(data)
        for i in range(self._get_num_block(data)):
            gamma = self._cipher_obj.encrypt(self._counter)
            self._counter = self._inc_ctr(self._counter)
            result = result + add_xor(self._get_block(data, i), gamma)
        if len(data) % self.block_size != 0:
            gamma = self._cipher_obj.encrypt(self._counter)
            self._counter = self._inc_ctr(self._counter)
            result = result + add_xor(
                data[self.block_size * self._get_num_block(data)::], gamma
            )
        return result

    def decrypt(self, data: bytearray) -> bytearray:
        """
        Ciphertext decryption in CTR mode.

        Args:
            data: Ciphertext data to be decrypted (as a byte object).

        Returns:
            Plaintext data (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid ciphertext data'): In
              case where the ciphertext data is not byte object.
        """
        data = super().decrypt(data)
        return self.encrypt(data)


class GOST34132015mac(GOST34132015):
    """
    Class that implements MAC mode.

    This class is the subclass of the 'GOST3413205' class and inherits the \
    'clear()' method and the 'block_size' attribute.

    Methods:
        update(): Update the MAC object with the bytes-like object.
        digest(): Calculating the Message authentication code of the data
          passed to the 'update()' method so far.
        hexdigest(): Calculating the Message authentication code of the data
          passed to the 'update()' method so far an return it of the
          hexadecimal.
        clear(): Clearing the values of iterative cipher keys.

    Attributes:
        block_size: An integer value the internal block size of the cipher
          algorithm in bytes.
    """

    def __init__(self, algorithm: str, key: bytearray, data: bytearray) -> None:
        """
        Initialize the ciphering object in MAC mode.

        Args:
            algorithm: The string with the name of the ciphering algorithm.
            key: Encryption key.
            data: Message to calculate MAC.
        """
        super().__init__(algorithm, key)
        value_r = self._cipher_obj.encrypt(bytearray(self._cipher_obj.block_size * b'\x00'))
        self._key_1, self._key_2 = self._get_mac_key(value_r)
        self._fin_buff = bytearray()
        self._iter_buf = bytearray()
        self._prev_mac = bytearray(self._cipher_obj.block_size)
        self._cur_mac = bytearray(self._cipher_obj.block_size)
        if data != bytearray(b''):
            self.update(data)

    def _set_pad_mode_3(self, data: bytearray) -> bytearray:
        if self._get_pad_size(data) == 0:
            result = data
        else:
            result = data + b'\x80' + b'\x00' * (self._get_pad_size(data) - 1)
        return result

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

        Args:
            data: The data from which to get the MAC (as a byte object).
              Repeated calls are equivalent to a single call with the
              concatenation of all the arguments: 'm.update(a)'; 'm.update(b)'
              is equivalent to 'm.update(a+b)'.

        Raises:
            GOSTCipherError('GOSTCipherError: invalid text data'): In case
              where the text data is not byte object.
        """
        if not isinstance(data, (bytes, bytearray)):
            self.clear()
            raise GOSTCipherError('GOSTCipherError: invalid text data')
        data = self._iter_buf + data
        block = bytearray()
        prev_block = self._cur_mac
        for i in range(0, self._get_num_block(data) - 1):
            block = self._cipher_obj.encrypt(add_xor(prev_block, self._get_block(data, i)))
            prev_block = block
        if self._get_pad_size(data) == 0:
            block = (
                self._cipher_obj.encrypt(
                    add_xor(prev_block, data[len(data) - self.block_size:len(data)])
                )
            )
            self._cur_mac = block
            self._prev_mac = prev_block
            self._iter_buf = bytearray(b'')
        else:
            begin_data = len(data) - 2 * self.block_size + self._get_pad_size(data)
            end_data = len(data) - self.block_size + self._get_pad_size(data)
            block = (
                self._cipher_obj.encrypt(
                    add_xor(prev_block, data[begin_data:end_data])
                )
            )
            self._cur_mac = block
            self._prev_mac = block
            self._iter_buf = data[len(data) - self.block_size + self._get_pad_size(data):]
        self._fin_buff = data[self.block_size * (self._get_num_block(data) - 1):]

    def mac_final(self) -> bytearray:
        """Return the final value of the MAC."""
        if self._get_pad_size(self._fin_buff) == 0:
            final_key = self._key_1
        else:
            final_key = self._key_2
            self._fin_buff = self._set_pad_mode_3(self._fin_buff[self.block_size:])
        result = bytearray()
        result = self._cipher_obj.encrypt(
            add_xor(add_xor(self._fin_buff, self._prev_mac), final_key)
        )
        return result

    def digest(self, mac_size: int) -> bytearray:
        """
        Calculate the Message authentication code (MAC).

        This method can be called after applying the 'update ()' method, or
        after calling the 'new ()' function with the data passed to it for MAC
        calculation.

        Args:
            mac_size: Message authentication code size (in bytes).

        Returns:
            Message authentication code value (as a byte object).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid message authentication
              code size'): In case of the invalid message authentication code
              size.
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

        Args:
            mac_size: Message authentication code size (in bytes).

        Returns:
            Message authentication code value in hexadecimal (as a hexadecimal
              string).

        Raises:
            GOSTCipherError('GOSTCipherError: invalid message authentication
              code size'): In case of the invalid message authentication code
              size.
        """
        return self.digest(mac_size).hex()


class GOSTCipherError(Exception):
    """
    The exception class.

    This is a class that implements exceptions that can occur when input data
    is incorrect.
    """
