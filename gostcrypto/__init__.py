"""
The GOST cryptographic functions.

The package 'goscrypto' implements various cryptographic functions defined in
the State standards of the Russian Federation.  All cryptographic
functionalities are organized in modules; each modules is dedicated to solving
a specific class of problems.

This package includes modules:
    - gostcrypto.gosthash: The module implements functions for calculating hash
      amounts in accordance with GOST R 34.11-2012.
    - gostcrypto.gostcipher: The module implements block encryption functions in
      accordance with GOST R 34.12-2015 and their use modes in accordance with
      GOST R 34.13-201.
    - gostcrypto.gostsignature: The module implements the functions of forming
      and verifying an electronic digital signature in accordance with
      GOST R 34.10-2012.
    - gostcrypto.gostrandom: The module implements functions for generating
      pseudo-random sequences in accordance with R 1323565.1.006-2017.
    - gostcrypto.gosthmac: The module implements the functions of calculating
      the HMAC message authentication code in accordance with R 50.1.113-2016.
    - gostcrypto.gostpbkdf: The module implements the password-based key
      derivation function in accordance with R 50.1.111-2016.
    - gostcrypto.gostoid: The module that implements functions for encoding and
      converting object identifiers.

Documentation:
    https://gostcrypto.readthedocs.io/.

Source code:
    https://github.com/drobotun/gostcrypto.
"""

from sys import version_info
from sys import exit as sys_exit

if version_info.major < 3 or version_info.minor < 6:
    print('Use python version 3.6 or higher')
    sys_exit()

__title__ = 'gostcrypto'
__version__ = '1.2.5'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from gostcrypto import gosthash
from gostcrypto import gostcipher
from gostcrypto import gostsignature
from gostcrypto import gostrandom
from gostcrypto import gosthmac
from gostcrypto import gostpbkdf
from gostcrypto import gostoid
