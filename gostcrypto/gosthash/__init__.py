"""
The GOST hashing functions.

The module that implements the 'Streebog' hash calculation algorithm in
accordance with GOST 34.11-2012 with a hash size of 512 bits and 256 bits.
The module includes the 'GOST34112012' class, the 'GOSTHashError' class and
several general functions.
"""

from .gost_34_11_2012 import (
    GOST34112012,
    new,
    GOSTHashError
)

__all__ = (
    'new',
    'GOSTHashError'
)
