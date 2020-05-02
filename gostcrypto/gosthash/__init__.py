"""The GOST hashing functions."""

from .gost_34_11_2012 import (
    GOST34112012,
    new,
    GOSTHashError
)

__all__ = (
    'new',
    'GOSTHashError'
)
