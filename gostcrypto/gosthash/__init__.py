"""
The GOST hashing functions.

The module that implements the 'Streebog' hash calculation algorithm
in accordance with GOST 34.11-2012 with a hash size of 512 bits and
256 bits.
"""

__title__ = 'gosthash'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from .gost_34_11_2012 import (
    GOST34112012,
    new,
    GOSTHashError
)
