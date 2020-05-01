"""The GOST cryptographic functions."""

__title__ = 'gostcipher'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from .gost_34_12_2015 import (
    GOST34122015Kuznechik,
    GOST34122015Magma
)

from .gost_34_13_2015 import (
    new,
    MODE_ECB,
    MODE_CBC,
    MODE_CFB,
    MODE_OFB,
    MODE_CTR,
    MODE_MAC,
    PAD_MODE_1,
    PAD_MODE_2,
    GOSTCipherError
)

__all__ = (
    'new',
    'MODE_ECB',
    'MODE_CBC',
    'MODE_CFB',
    'MODE_OFB',
    'MODE_CTR',
    'MODE_MAC',
    'PAD_MODE_1',
    'PAD_MODE_2',
    'GOSTCipherError'
)
