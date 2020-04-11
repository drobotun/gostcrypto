"""The package implements various cryptographic functions defined in the State standards
   of the Russian Federation. It includes the following modules:

      - gosthash: The module implements functions for calculating hash amounts in accordance
                  with GOST R 34.11-2012.

      - gostcipher: The module implements block encryption functions in accordance with
                    GOST R 34.12-2015 and their use modes in accordance with GOST R 34.13-2015.

      - gostsignature: The module implements the functions of forming and verifying an
                       electronic digital signature in accordance with GOST R 34.10-2012.

      - gostrandom: The module implements functions for generating pseudo-random sequences
                    in accordance with R 1323565.1.006-2017.

      - gosthmac: The module implements the functions of calculating the HMAC message
                  authentication code in accordance with R 50.1.113-2016.

      - gostpbkdf: The module implements the password-based key derivation function in
                   accordance with R 50.1.111-2016.
"""
__title__ = 'gostcrypto'
__version__ = '1.0.0'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from . import gosthash # GOST34112012
from .gostcipher import GOST34122015Kuznechik, GOST34122015Magma
from .gostcipher import GOST34132015
from .gostsignature import GOST34102012
from .gostrandom import R132356510062017
from .gosthmac import R5011132016
from .gostpbkdf import R5011112016
