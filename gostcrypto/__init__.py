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

from .gosthash import GOST34112012, new

from .gostcipher import GOST34122015Kuznechik, GOST34122015Magma

from .gostcipher import GOST34132015, new, MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB,\
                        MODE_CTR, MODE_MAC, PAD_MODE_1, PAD_MODE_2, PAD_MODE_3
                        
from .gostsignature import GOST34102012, new, MODE_256, MODE_512, CURVES_R_1323565_1_024_2019
                           
from .gostrandom import R132356510062017, new, SIZE_S_384, SIZE_S_320, SIZE_S_256
                        
from .gosthmac import R5011132016, new

from .gostpbkdf import R5011112016, new
