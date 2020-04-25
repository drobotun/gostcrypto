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
    hash_obj = gostcrypto.gosthash.new('streebog256', data=hash_string))
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

    private_key = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
    digest = bytearray.fromhex('2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])
    
    signature = sign_obj.sign(private_key, digest)

Verify
------

.. code-block:: python

    public_key = bytearray.fromhex('fd21c21ab0dc84c154f3d218e9040bee64fff48bdff814b232295b09d0df72e45026dec9ac4f07061a2a01d7a2307e0659239a82a95862df86041d1458e45049')
    digest = bytearray.fromhex('2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')
    signature = bytearray.fromhex('4b6dd64fa33820e90b14f8f4e49ee92eb2660f9eeb4e1b313517b6ba173979656df13cd4bceaf606ed32d410f48f2a5c2596c146e8c2fa4455d08cf68fc2b2a7')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    if sign_obj.verify(public_key, digest, signature):
        print('Signature is correct')
    else:
        print('Signature is not correct')

Generating a public key
-----------------------

.. code-block:: python

    private_key = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    public_key = sign_obj.public_key_generate(private_key)

Usage gostrandom module
"""""""""""""""""""""""

.. code-block:: python

    import gostcrypto

    rand_k = bytearray([
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
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