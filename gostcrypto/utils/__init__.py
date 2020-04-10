"""The module that implements auxiliary functions for the operation of the
   GOSTcrypto module.
"""

__title__ = 'utils'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from .utils import msb, add_xor, zero_fill, bytearray_to_int,\
                   int_to_bytearray, compare, compare_to_zero
from .s_box import S_BOX, S_BOX_REVERSE
