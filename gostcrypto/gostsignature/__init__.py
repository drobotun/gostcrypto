"""
The GOST digital signature functions.

The module that implements processes for creating and verifying an electronic
digital signature according to GOST 34.10-2012.  The module includes the
'GOST34102012' class, the 'GOSTSignatureError' class, several general functions
and set of the parameters of elliptic curves (in accordance with
R 1323565.1.024-2019).

Attributes:
    MODE_256: 256-bit key signing mode.
    MODE_512: 512-bit key signing mode.
    CURVES_R_1323565_1_024_2019: Set of elliptic curve parameters in accordance
      R 1323565.1.024-2019.
"""

from .gost_34_10_2012 import (
    GOST34102012,
    new,
    GOSTSignatureError,
    MODE_256,
    MODE_512,
    CURVES_R_1323565_1_024_2019
)

__all__ = (
    'new',
    'MODE_256',
    'MODE_512',
    'CURVES_R_1323565_1_024_2019',
    'GOSTSignatureError'
)
