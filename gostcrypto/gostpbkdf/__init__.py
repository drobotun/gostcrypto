"""The module implementing the password-based key derivation function in accordance
with R 50.1.111-2016.
"""

__title__ = 'gostpbkdf'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from .r_50_1_111_2016 import (
    R5011112016,
    new,
    GOSTPBKDFError
)
