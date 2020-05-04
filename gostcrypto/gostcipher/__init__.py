"""
Block cipher modes according to GOST 34.13-2015.

The module implements the modes of operation of block encryption algorithms
"magma" and "kuznechik", described in GOST 34.13-2015.  The module includes
the base classes 'GOST3413205', 'GOST3413205Cipher', 'GOST3413205CipherPadding',
'GOST3413205CipherFeedBack', and classes 'GOST3413205ecb', 'GOST3413205cbc',
'GOST3413205cfb', 'GOST3413205ofb' and 'GOST3413205ctr'.  In addition the
module includes the GOSTCipherError class and several general functions.

Attributes:
    MODE_ECB: Electronic Codebook mode.
    MODE_CBC: Cipher Block Chaining mode.
    MODE_CFB: Cipher Feedback mode.
    MODE_OFB: OutputFeedback mode.
    MODE_CTR: Counter mode.
    MODE_MAC: Message Authentication Code algorithm.
    PAD_MODE_1: Message padding procedure No. 1 (paragraph 4.1.1
      GOST 34.13-2015)
    PAD_MODE_2: Message padding procedure No. 2 (paragraph 4.1.2
      GOST 34.13-2015)
"""

from .gost_34_12_2015 import (
    GOST34122015Kuznechik,
    GOST34122015Magma
)

from .gost_34_13_2015 import (
    new,
    MODE_ECB,
    MODE_CBC,
    MODE_CFB,
    MODE_OFB,
    MODE_CTR,
    MODE_MAC,
    PAD_MODE_1,
    PAD_MODE_2,
    GOSTCipherError
)

__all__ = (
    'new',
    'MODE_ECB',
    'MODE_CBC',
    'MODE_CFB',
    'MODE_OFB',
    'MODE_CTR',
    'MODE_MAC',
    'PAD_MODE_1',
    'PAD_MODE_2',
    'GOSTCipherError'
)
