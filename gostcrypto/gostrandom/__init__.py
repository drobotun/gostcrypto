"""
The GOST password-based key derivation function.

The module implementing the password-based key derivation function in accordance
with R 50.1.111-2016.
"""

__title__ = 'gostrandom'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from .r_1323565_1_006_2017 import (
    R132356510062017,
    new,
    GOSTRandomError,
    SIZE_S_384,
    SIZE_S_320,
    SIZE_S_256
)
