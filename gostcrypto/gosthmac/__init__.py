"""
The GOST hash-based message authentication code functions.

The module implementing the calculating the HMAC message authentication code
in accordance with R 50.1.113-2016.  The module includes the 'R5011132016'
class and 'GOSTHMACError' class and several general functions.
"""

from .r_50_1_113_2016 import (
    R5011132016,
    new,
    GOSTHMACError
)

__all__ = (
    'new',
    'GOSTHMACError'
)
