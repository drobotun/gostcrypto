"""The GOST pseudo-random sequence generation function."""

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
