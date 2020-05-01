"""The GOST hashing functions."""

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

__all__ = (
    'new',
    'GOSTHashError'
)
