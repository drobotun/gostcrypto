"""
The GOST pseudo-random sequence generation function.

The module that implements pseudo-random sequence generation in accordance
with R 1323565.1.006-2017.  The module includes the 'R132356510062017' class
and 'GOSTRandomError' class and several general functions.

Attributes:
    SIZE_S_384: The size of the initial filling (seed) is 384 bits.
    SIZE_S_320: The size of the initial filling (seed) is 320 bits.
    SIZE_S_256: The size of the initial filling (seed) is 256 bits.
"""

from .r_1323565_1_006_2017 import (
    R132356510062017,
    new,
    GOSTRandomError,
    SIZE_S_384,
    SIZE_S_320,
    SIZE_S_256
)

__all__ = (
    'new',
    'GOSTRandomError',
    'SIZE_S_384',
    'SIZE_S_320',
    'SIZE_S_256'
)
