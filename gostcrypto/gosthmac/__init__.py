"""The GOST hash-based message authentication code functions."""

from .r_50_1_113_2016 import (
    R5011132016,
    new,
    GOSTHMACError
)

__all__ = (
    'new',
    'GOSTHMACError'
)
