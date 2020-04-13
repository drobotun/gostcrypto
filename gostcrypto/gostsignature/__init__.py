"""The module that implements processes for creating and verifying an electronic digital
signature according to GOST 34.10-2012.
"""

__title__ = 'gostsignature'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from .gost_34_10_2012 import (
    GOST34102012,
    new,
    GOSTSignatureError,
    MODE_256,
    MODE_512,
    CURVES_R_1323565_1_024_2019
)
