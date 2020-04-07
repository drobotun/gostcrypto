"""The module that implements various block encryption modes (ECB, CBC, CFB, OFB, CTR and
   MAC according to GOST 34.13-2015.
"""

__title__ = 'gostcipher'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from .gost_34_12_2015 import *
from .gost_34_13_2015 import *
