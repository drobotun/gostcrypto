"""
The object identifier encoding functions.

The module that implements functions for encoding and converting object
identifiers. The module includes the 'ObjectIdentifier' class, the
'GOSTOIDError' class, constants and several general functions.

Attributes:
    OBJECT_IDENTIFIER_TC26: A set of object identifiers (OIDs) of the Technical
      Committee for standardization "Cryptographic information protection"
      (TC 26).
"""

from .oid import (
    OBJECT_IDENTIFIER_TC26,
    ObjectIdentifier,
    GOSTOIDError
)

__all__ = (
    'OBJECT_IDENTIFIER_TC26',
    'ObjectIdentifier',
    'GOSTOIDError'
)
