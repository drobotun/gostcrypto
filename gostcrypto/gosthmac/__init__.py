"""
The GOST hash-based message authentication code functions.

The module implementing the calculating the HMAC message authentication code
in accordance with R 50.1.113-2016.
"""

__title__ = 'gosthmac'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from .r_50_1_113_2016 import (
    R5011132016,
    new,
    GOSTHMACError
)
