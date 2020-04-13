"""The module that implements various block encryption modes (ECB, CBC, CFB, OFB, CTR and
   MAC according to GOST 34.13-2015.
"""

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
    GOST34132015,
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
