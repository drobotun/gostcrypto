GOST cryptographic functions
============================

.. image:: https://img.shields.io/github/license/drobotun/virustotalapi3?style=flat
    :target: http://doge.mit-license.org
.. image:: https://img.shields.io/travis/drobotun/gostcrypto
    :target: https://travis-ci.org/drobotun/gostcrypto
.. image:: https://ci.appveyor.com/api/projects/status/3inl1huy5unq1q60?svg=true
    :target: https://ci.appveyor.com/project/drobotun/gostcrypto
.. image:: https://img.shields.io/coveralls/github/drobotun/gostcrypto
    :target: https://coveralls.io/github/drobotun/gostcrypto
.. image:: https://api.codacy.com/project/badge/Grade/774f6fd50f224286ac1e566d752bd9c6
    :target: https://app.codacy.com/manual/drobotun/gostcrypto/dashboard
.. image:: https://readthedocs.org/projects/gostcrypto/badge/?version=latest
    :target: https://gostcrypto.readthedocs.io/en/latest/?badge=latest
.. image:: https://img.shields.io/pypi/pyversions/gostcrypto.svg?logo=python&logoColor=FBE072
    :target: https://pypi.org/project/gostcrypto/
.. image:: https://img.shields.io/pypi/v/gostcrypto
    :target: https://pypi.org/project/gostcrypto/
.. image:: https://img.shields.io/pypi/format/gostcrypto
    :target: https://pypi.org/project/gostcrypto/

The package implements various cryptographic functions defined in the State standards of the Russian Federation. It includes the following modules:

- **gosthash**: The module implements functions for calculating hash amounts in accordance with GOST R 34.11-2012.
- **gostcipher**: The module implements block encryption functions in accordance with GOST R 34.12-2015 and their use modes in accordance with GOST R 34.13-2015.
- **gostsignature**: The module implements the functions of forming and verifying an electronic digital signature in accordance with GOST R 34.10-2012.
- **gostrandom**: The module implements functions for generating pseudo-random sequences in accordance with R 1323565.1.006-2017.
- **gosthmac**: The module implements the functions of calculating the HMAC message authentication code in accordance with R 50.1.113-2016.
- **gostpbkdf**: The module implements the password-based key derivation function in accordance with R 50.1.111-2016.

Installation
""""""""""""

.. code-block:: bash

    $ pip install gostcrypto

Usage **'gosthash'** module
"""""""""""""""""""""""""""

Getting a hash for a string
---------------------------

.. code-block:: python

    import gostcrypto

    hash_string = u'Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы'.encode('cp1251')
    hash_obj = gostcrypto.gosthash.new('streebog256')
    hash_obj.update(hash_string)
    result = hash_obj.hexdigest()

Getting a hash for a file
-------------------------

In this case the ``buffer_size`` value must be a multiple of the ``block_size`` value.

.. code-block:: python

    import gostcrypto

    file_path = 'd:/hash file.txt'
    buffer_size = 128
    hash_obj = gostcrypto.gosthash.new('streebog512')
    with open(file_path, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hash_obj.update(buffer)
            buffer = file.read(buffer_size)
    result = hash_obj.hexdigest()

Usage **'gostcipher'** module
"""""""""""""""""""""""""""""

String encryption in ECB mode
-----------------------------

.. code-block:: python

    import gostcrypto

    key = bytearray([
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ])

    plain_text = = bytearray([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11,
    ])

    cipher_obj = gostcrypto.gostcipher.new('kuznechik',
                                            key,
                                            gostcrypto.gostcipher.MODE_ECB,
                                            pad_mode=PAD_MODE_1)

    cipher_text = cipher_obj.encrypt(plain_text)

File encryption in CTR mode
---------------------------

In this case the ``buffer_size`` value must be a multiple of the ``block_size`` value.

.. code-block:: python

    import gostcrypto

    key = bytearray([
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ])

    init_vect = bytearray([
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0,
    ])

    plain_file_path = 'd:/plain file.txt'
	cipher_file_path = 'd:/cipher file.txt'
    cipher_obj = gostcrypto.gostcipher.new('kuznechik',
                                            key,
                                            gostcrypto.gostcipher.MODE_CTR,
                                            init_vect=init_vect)

    buffer_size = 128
    plain_file = open(plain_file_path, 'rb')
    cipher_file = open(cipher_file_path', 'wb')
    buffer = plain_file.read(buffer_size)
    while len(buffer) > 0:
        cipher_data = cipher.decrypt(buffer)
        cipher_file.write(cipher_data)
        buffer = plain_file.read(buffer_size)

Calculating MAC of the file
---------------------------

In this case the ``buffer_size`` value must be a multiple of the ``block_size`` value.

.. code-block:: python

    import gostcrypto

    key = bytearray([
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ])

    file_path = 'd:/file.txt'
    cipher = gostcrypto.gostcipher.new('kuznechik',
                                        key,
                                        gostcrypto.gostcipher.MODE_MAC,
                                        pad_mode=gostcrypto.gostcipher.PAD_MODE_3)
    
	buffer_size = 128
	file = open(file_path, 'rb')
    buffer = file.read(buffer_size)
    while len(buffer) > 0:
        cipher.update(buffer)
        buffer = file.read(buffer_size)
    mac_result = cipher.digest(8)

Usage **'gostsignature'** module
""""""""""""""""""""""""""""""""

Signing
-------

.. code-block :: python

    import gostcrypto

    private_key = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
    digest = bytearray.fromhex('2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])
    
    signature = sign_obj.sign(private_key, digest)

Verify
------

.. code-block:: python

    import gostcrypto

    public_key = bytearray.fromhex('7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da')
    digest = bytearray.fromhex('2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')
    signature = bytearray.fromhex('41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc049301456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    if sign_obj.verify(public_key, digest, signature):
        print('Signature is correct')
    else:
        print('Signature is not correct')

Generating a public key
-----------------------

.. code-block:: python

    import gostcrypto

    private_key = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    public_key = sign_obj.public_key_generate(private_key)

Usage **'gostrandom'** module
"""""""""""""""""""""""""""""

.. code-block:: python

    import gostcrypto

    rand_k = bytearray([
        0xa8, 0xe2, 0xf9, 0x00, 0xdd, 0x4d, 0x7e, 0x24,
        0x5f, 0x09, 0x75, 0x3d, 0x01, 0xe8, 0x75, 0xfc,
        0x38, 0xf1, 0x4f, 0xf5, 0x25, 0x4c, 0x94, 0xea,
        0xdb, 0x45, 0x1e, 0x4a, 0xb6, 0x03, 0xb1, 0x47,
    ])

    random_obj = gostcrypto.gostrandom.new(32,
                                           rand_k,
                                           gostcrypto.gostrandom.SIZE_S_320)
    random_result = random_obj.random()
    random_obj.clear()

Usage **'gosthmac'** module
"""""""""""""""""""""""""""

Getting a HMAC for a string
---------------------------

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f1011121315161718191a1b1c1d1e1f')
    data = bytearray.fromhex('0126bdb87800af214341456563780100')

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    hmac_obj.update(data)
    result = hmac_obj.digest()

Getting a HMAC for a file
-------------------------

In this case the ``buffer_size`` value must be a multiple of the ``block_size`` value.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f1011121315161718191a1b1c1d1e1f')
    file_path = 'd:/file.txt'

    buffer_size = 128
    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    with open(file_path, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hmac_obj.update(buffer)
            buffer = file.read(buffer_size)
    result = hmac_obj.hexdigest()

Usage **'gostpbkdf'** module
""""""""""""""""""""""""""""

.. code-block:: python

    import gostcrypto

    password = b'password'
    salt = b'salt'

    pbkdf_obj = new(password, salt, 4096)
    pbkdf_result = pbkdf_obj.derive(32)

License
"""""""

MIT Copyright (c) 2020 Evgeny Drobotun

Documentation
"""""""""""""

Documentation for using this package: https://gostcrypto.readthedocs.io/
