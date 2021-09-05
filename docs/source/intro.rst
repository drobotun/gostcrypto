Introduction
============

Overview
~~~~~~~~

The package **goscrypto** implements various cryptographic functions defined in the State standards of the Russian Federation. All cryptographic functionalities are organized in modules; each modules is dedicated to solving a specific class of problems.

.. csv-table::
    :header: **Package**, **Description**
    :widths: 40, 80

    :doc:`gostcrypto.gosthash <api/gosthash/gosthash>`, "The module implements functions for calculating hash amounts in accordance with `GOST R 34.11-2012 <https://files.stroyinf.ru/Data2/1/4293788/4293788459.pdf>`_."
    :doc:`gostcrypto.gostcipher <api/gostcipher/gostcipher>`, "The module implements block encryption functions in accordance with `GOST R 34.12-2015 <https://files.stroyinf.ru/Data/603/60339.pdf>`_ and their use modes in accordance with `GOST R 34.13-2015 <https://files.stroyinf.ru/Data2/1/4293762/4293762703.pdf>`_."
    :doc:`gostcrypto.gostsignature <api/gostsignature/gostsignature>`, "The module implements the functions of forming and verifying an electronic digital signature in accordance with `GOST R 34.10-2012 <https://files.stroyinf.ru/Data2/1/4293788/4293788463.pdf>`_."
    :doc:`gostcrypto.gostrandom <api/gostrandom/gostrandom>`, "The module implements functions for generating pseudo-random sequences in accordance with `R 1323565.1.006-2017 <https://files.stroyinf.ru/Data2/1/4293740/4293740893.pdf>`_."
    :doc:`gostcrypto.gosthmac <api/gosthmac/gosthmac>`, "The module implements the functions of calculating the HMAC message authentication code in accordance with `R 50.1.113-2016 <https://files.stroyinf.ru/Data2/1/4293748/4293748842.pdf>`_."
    :doc:`gostcrypto.gostpbkdf <api/gostpbkdf/gostpbkdf>`, "The module implements the password-based key derivation function in accordance with `R 50.1.111-2016 <https://files.stroyinf.ru/Data2/1/4293748/4293748845.pdf>`_."
	:doc:`gostcrypto.gostoid <api/gostoid/gostoid>`, "The module implements generating identifiers for cryptographic objects."

Features
""""""""

- **Symmetric ciphers:**

    - kuznechik
    - magma

- **Traditional modes of operations for symmetric ciphers:**

    - ECB
    - CBC
    - CFB
    - OFB
    - CTR
 
- **Cryptographic hashes:**
 
    - streebog 512
    - streebog 256
 
- **Message Authentication Codes (MAC):**

    - MAC
    - HMAC	

- **Asymmetric digital signatures:**

    - (EC)DSA

- **Key derivation:**

    - PBKDF2

Installation
""""""""""""

.. code-block:: bash

    $ pip install gostcrypto

Usage gosthash module
"""""""""""""""""""""

Getting a hash for a string
---------------------------

.. code-block:: python

    import gostcrypto

    hash_string = u'Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы'.encode('cp1251')
    hash_obj = gostcrypto.gosthash.new('streebog256', data=hash_string)
    hash_result = hash_obj.hexdigest()

Getting a hash for a file
-------------------------

.. Note::
    In this case the ``buffer_size`` value must be a multiple of the ``block_size`` value.

.. code-block:: python

    import gostcrypto

    file_path = 'hash_file.txt'
    buffer_size = 128
    hash_obj = gostcrypto.gosthash.new('streebog512')
    with open(file_path, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hash_obj.update(buffer)
            buffer = file.read(buffer_size)
    hash_result = hash_obj.hexdigest()

Getting the name identifier of the hashing algorithm object
-----------------------------------------------------------

.. code-block:: python

    import gostcrypto

    hash_obj = gostcrypto.gosthash.new('streebog512')
    oid_name = hash_obj.oid.name

Usage gostcipher module
"""""""""""""""""""""""

String encryption in ECB mode
-----------------------------

.. code-block:: python

    import gostcrypto

    key = bytearray([
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ])

    plain_text = bytearray([
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11,
    ])

    cipher_obj = gostcrypto.gostcipher.new('kuznechik',
                                            key,
                                            gostcrypto.gostcipher.MODE_ECB,
                                            pad_mode=gostcrypto.gostcipher.PAD_MODE_1)

    cipher_text = cipher_obj.encrypt(plain_text)

File encryption in CTR mode
---------------------------

.. note::
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

    plain_file_path = 'plain_file.txt'
    cipher_file_path = 'cipher_file.txt'
    cipher_obj = gostcrypto.gostcipher.new('kuznechik',
                                            key,
                                            gostcrypto.gostcipher.MODE_CTR,
                                            init_vect=init_vect)

    buffer_size = 128

    plain_file = open(plain_file_path, 'rb')
    cipher_file = open(cipher_file_path, 'wb')
    buffer = plain_file.read(buffer_size)
    while len(buffer) > 0:
        cipher_data = cipher_obj.encrypt(buffer)
        cipher_file.write(cipher_data)
        buffer = plain_file.read(buffer_size))

Calculating MAC of the file
---------------------------

.. note::
    In this case the ``buffer_size`` value must be a multiple of the ``block_size`` value.

.. code-block:: python

    import gostcrypto

    key = bytearray([
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ])

    plain_file_path = 'plain_file.txt'
    cipher_obj = gostcrypto.gostcipher.new('kuznechik',
                                            key,
                                            gostcrypto.gostcipher.MODE_MAC)

    buffer_size = 128

    plain_file = open(plain_file_path, 'rb')
    buffer = plain_file.read(buffer_size)
    while len(buffer) > 0:
        cipher_obj.update(buffer)
        buffer = plain_file.read(buffer_size)
    mac_result = cipher_obj.digest(8)

Usage gostsignature module
""""""""""""""""""""""""""

Signing
-------

.. code-block :: python

    import gostcrypto

    private_key = bytearray([
        0x7a, 0x92, 0x9a, 0xde, 0x78, 0x9b, 0xb9, 0xbe, 0x10, 0xed, 0x35, 0x9d, 0xd3, 0x9a, 0x72, 0xc1,
        0x1b, 0x60, 0x96, 0x1f, 0x49, 0x39, 0x7e, 0xee, 0x1d, 0x19, 0xce, 0x98, 0x91, 0xec, 0x3b, 0x28,
    ])

    digest = bytearray([
        0x2d, 0xfb, 0xc1, 0xb3, 0x72, 0xd8, 0x9a, 0x11, 0x88, 0xc0, 0x9c, 0x52, 0xe0, 0xee, 0xc6, 0x1f,
        0xce, 0x52, 0x03, 0x2a, 0xb1, 0x02, 0x2e, 0x8e, 0x67, 0xec, 0xe6, 0x67, 0x2b, 0x04, 0x3e, 0xe5,
    ])

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
        gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])
    
    signature = sign_obj.sign(private_key, digest)

Verify
------

.. code-block:: python

    public_key = bytearray([
        0xfd, 0x21, 0xc2, 0x1a, 0xb0, 0xdc, 0x84, 0xc1, 0x54, 0xf3, 0xd2, 0x18, 0xe9, 0x04, 0x0b, 0xee,
        0x64, 0xff, 0xf4, 0x8b, 0xdf, 0xf8, 0x14, 0xb2, 0x32, 0x29, 0x5b, 0x09, 0xd0, 0xdf, 0x72, 0xe4,
        0x50, 0x26, 0xde, 0xc9, 0xac, 0x4f, 0x07, 0x06, 0x1a, 0x2a, 0x01, 0xd7, 0xa2, 0x30, 0x7e, 0x06,
        0x59, 0x23, 0x9a, 0x82, 0xa9, 0x58, 0x62, 0xdf, 0x86, 0x04, 0x1d, 0x14, 0x58, 0xe4, 0x50, 0x49,
    ])

    digest = bytearray([
        0x2d, 0xfb, 0xc1, 0xb3, 0x72, 0xd8, 0x9a, 0x11, 0x88, 0xc0, 0x9c, 0x52, 0xe0, 0xee, 0xc6, 0x1f,
        0xce, 0x52, 0x03, 0x2a, 0xb1, 0x02, 0x2e, 0x8e, 0x67, 0xec, 0xe6, 0x67, 0x2b, 0x04, 0x3e, 0xe5,
    ])

    signature = bytearray([
        0x4b, 0x6d, 0xd6, 0x4f, 0xa3, 0x38, 0x20, 0xe9, 0x0b, 0x14, 0xf8, 0xf4, 0xe4, 0x9e, 0xe9, 0x2e,
        0xb2, 0x66, 0x0f, 0x9e, 0xeb, 0x4e, 0x1b, 0x31, 0x35, 0x17, 0xb6, 0xba, 0x17, 0x39, 0x79, 0x65,
        0x6d, 0xf1, 0x3c, 0xd4, 0xbc, 0xea, 0xf6, 0x06, 0xed, 0x32, 0xd4, 0x10, 0xf4, 0x8f, 0x2a, 0x5c,
        0x25, 0x96, 0xc1, 0x46, 0xe8, 0xc2, 0xfa, 0x44, 0x55, 0xd0, 0x8c, 0xf6, 0x8f, 0xc2, 0xb2, 0xa7,
    ])

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
        gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    if sign_obj.verify(public_key, digest, signature):
        print('Signature is correct')
    else:
        print('Signature is not correct')

Generating a public key
-----------------------

.. code-block:: python

    private_key = bytearray([
        0x7a, 0x92, 0x9a, 0xde, 0x78, 0x9b, 0xb9, 0xbe, 0x10, 0xed, 0x35, 0x9d, 0xd3, 0x9a, 0x72, 0xc1,
        0x1b, 0x60, 0x96, 0x1f, 0x49, 0x39, 0x7e, 0xee, 0x1d, 0x19, 0xce, 0x98, 0x91, 0xec, 0x3b, 0x28,
    ])

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
        gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    public_key = sign_obj.public_key_generate(private_key)

Getting the identifier of the signature mode object name
--------------------------------------------------------

.. code-block:: python

    import gostcrypto

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
        gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])
    oid_name = sign_obj.oid.name

Usage gostrandom module
"""""""""""""""""""""""

.. code-block:: python

    import gostcrypto

    rand_k = bytearray([
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ])

    random_obj = gostcrypto.gostrandom.new(32,
                                           rand_k=rand_k,
                                           size_s=gostcrypto.gostrandom.SIZE_S_256)
    random_result = random_obj.random()
    random_obj.clear()

Usage gosthmac module
"""""""""""""""""""""

Getting a HMAC for a string
---------------------------

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f1011121315161718191a1b1c1d1e1f')
    data = bytearray.fromhex('0126bdb87800af214341456563780100')

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key, data=data)
    hmac_result = hmac_obj.digest()

Getting a HMAC for a file
-------------------------

.. note::
    In this case the ``buffer_size`` value must be a multiple of the ``block_size`` value.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f1011121315161718191a1b1c1d1e1f')
    file_path = 'hmac_file.txt'
    buffer_size = 128
    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    with open(file_path, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hmac_obj.update(buffer)
            buffer = file.read(buffer_size)
    hmac_result = hmac_obj.hexdigest()

Getting the name identifier of the HMAC algorithm object
--------------------------------------------------------

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f1011121315161718191a1b1c1d1e1f')
    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    oid_name = hmac_obj.oid.name

Usage gostpbkdf module
""""""""""""""""""""""

.. code-block:: python

    import gostcrypto

    password = b'password'
    salt = b'salt'

    pbkdf_obj = gostcrypto.gostpbkdf.new(password, salt=salt, counter=4096)
    pbkdf_result = pbkdf_obj.derive(32)

License
~~~~~~~

MIT Copyright (c) 2020 Evgeny Drobotun

Source code
~~~~~~~~~~~

Package source code: https://github.com/drobotun/gostcrypto

Release History
~~~~~~~~~~~~~~~

.. rubric:: 1.2.5 (05.09.2021)

- Fixed a several minor bugs

.. rubric:: 1.2.4 (17.09.2020)

- Fixed a default initial vector bug (added default initial vector for 'magma' algorithm)

.. rubric:: 1.2.3 (23.05.2020)

- Added Python version checking (use version 3.6 or higher)

.. rubric:: 1.2.2 (15.05.2020)

- Fixed a MAC calculation bug when using padding in the **gostcipher** module (in earlier versions (including 1.2.1), the MAC with padding was calculated incorrectly (the bug was in the 'msb' and 'update' functions))

.. rubric:: 1.2.1 (13.05.2020)

- Fixed a MAC calculation bug when using padding in the **gostcipher** module

.. rubric:: 1.2.0 (07.05.2020)

- Refactoring and code modification in module **gostcipher** to increase the performance of encryption algorithm 'kuznechik' (uses precomputation  values of the 'gf' function;  the performance of the encryption function has increased by an average of 5..10 times)
- Refactoring and code modification in module **gosthash** to increase the performance of hasing (uses precomputation  values of the 'l, s and p-transformation',  function;  the performance of the encryption function has increased by an average of 2..7 times)
- Added the **gostoid** module that implements generating cryptographic object IDs for the **gostcipher**, **gosthash**, **gosthmac** and **gostsignature** modules

.. rubric:: 1.1.2 (02.05.2020)

- Refactoring **gostcipher** module (changed the class hierarchy to remove code duplication)
- Refactoring **gosthash** module (remove code duplication)
- Fixed some minor bugs
- Updated docstring in accordance with the Google Python Style Guide

.. rubric:: 1.1.1 (20.04.2020)

- Use ``**kvargs`` in the ``new`` function with default parameters (**gostrandom**, **gosthash**, **gosthmac**, **gostpbkdf**)
- Add the ability to pass data to the ``new`` function from **gosthmac**
- Fixed some minor bugs in the **gostrandom** module

.. rubric:: 1.1.0 (15.04.2020)

- Refactoring code **gostcipher** module (changed the class structure)
- Each module has its own exception class added
- In the ``new`` function of the **gostcipher** module for MAC mode, it is now possible to pass data for MAC calculation, followed by calling the ``digest`` method without first calling the ``update`` method
- In the ``new`` function of the **gosthash** module, it is now possible to pass data for hash calculation, followed by calling the ``digest`` method without first calling the ``update`` method
- Added new exceptions for various conflict situations
- Fixed some minor bugs

.. rubric:: 1.0.0 (08.04.2020)

- First release of **'gostcrypto'**
