GOST cryptographic functions
============================

.. image:: https://img.shields.io/github/license/drobotun/virustotalapi3?style=flat
    :target: http://doge.mit-license.org
.. image:: https://img.shields.io/travis/drobotun/gostcrypto
    :target: https://travis-ci.org/drobotun/gostcrypto
.. image:: https://img.shields.io/coveralls/github/drobotun/gostcrypto
    :target: https://coveralls.io/github/drobotun/gostcrypto

The package implements various cryptographic functions defined in the State standards of the Russian Federation. It includes the following modules:

- **gosthash**: The module implements functions for calculating hash amounts in accordance with GOST R 34.11-2012.
- **gostcipher**: The module implements block encryption functions in accordance with GOST R 34.12-2015 and their use modes in accordance with GOST R 34.13-2015.
- **gostsignature**: The module implements the functions of forming and verifying an electronic digital signature in accordance with GOST R 34.10-2012.
- **gostrandom**: The module implements functions for generating pseudo-random sequences in accordance with R 1323565.1.006-2017.
- **gosthmac**: The module implements the functions of calculating the HMAC message authentication code in accordance with R 50.1.113-2016.
- **gostpbkdf**: The module implements the password-based key derivation function in accordance with R 50.1.111-2016.

The 'gosthash' module.
----------------------

Usage:
~~~~~~

.. rubric:: **Getting a hash for a string:**

.. code-block:: python

    import gostcrypto

    hasher = gostcrypto.gosthash.new('streebog256')
    hasher.update(b'<string>')
    result = hasher.hexdigest()

.. rubric:: **Getting a hash for a file:**

.. code-block:: python

    import gostcrypto

    #The 'buffer_size' must be a multiple of 64
    buffer_size = 128
    hasher = gostcrypto.gosthash.new('streebog512')
    with open(<'file path'>, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hasher.update(buffer)
            buffer = file.read(buffer_size)
    result = hasher.hexdigest()

The 'gostcipher' module.
------------------------

Usage:
~~~~~~

.. rubric:: **Encrypting a string:**

.. code-block:: python

    import gostcrypto

    CIPHER_KEY = bytearray([
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    ])

    cipher = gostcrypto.gostcipher.new('kuznechik',
                                        CIPHER_KEY,
                                        gostcrypto.gostcipher.MODE_ECB)
    cipher_string = cipher.encrypt(b'<plain string>')

.. rubric:: **Encrypting a file:**

.. code-block:: python

    import gostcrypto

    CIPHER_KEY = bytearray([
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    ])

    CIPHER_IV = bytearray([
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0,
    ])

    cipher = gostcrypto.gostcipher.new('kuznechik',
                                        CIPHER_KEY,
                                        gostcrypto.gostcipher.MODE_CTR,
                                        init_vect=CIPHER_IV)

    #The 'buffer_size' must be a multiple of the block size
    buffer_size = 128
    file_in = open('<path to the plain text file>', 'rb')
    file_out = open('<path to the encrypted text file>', 'wb')
    buffer = file_in.read(buffer_size)
    while len(buffer) > 0:
        block = cipher.decrypt(buffer)
        file_out.write(block)
        buffer = file_in.read(buffer_size)

.. rubric:: **Calculating MAC of the file:**

.. code-block:: python

    import gostcrypto

    CIPHER_KEY = bytearray([
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    ])

    #The 'buffer_size' must be a multiple of the block size
    buffer_size = 128
    cipher = gostcrypto.gostcipher.new('kuznechik',
                                        CIPHER_KEY,
                                        gostcrypto.gostcipher.MODE_MAC,
                                        pad_mode=gostcrypto.gostcipher.PAD_MODE_3)
    file_in = open('<path to the file to calculate the MAC>', 'rb')
    buffer = file_in.read(buffer_size)
    while len(buffer) > 0:
        block = cipher.update(buffer)
        buffer = file_in.read(buffer_size)
    mac_result = cipher.digest(cipher.block_size)

The 'gostsignature' module.
---------------------------

Usage:
~~~~~~

.. rubric:: **Signing:**

.. code-block :: python

    import gostcrypto

    private_key = bytearray.fromhex(
                  '7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
    digest = bytearray.fromhex(
             '2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019
                                            ['id-tc26-gost-3410-2012-256-paramSetB'])
    signature = sign_obj.sign(private_key, digest)

.. rubric:: **Verify:**

.. code-block:: python

    import gostcrypto

    public_key = bytearray.fromhex(
                 '7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da')
    digest = bytearray.fromhex(
             '2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')
    signature = bytearray.fromhex(
                '41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc049301456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019
                                            ['id-tc26-gost-3410-2012-256-paramSetB'])
    if sign_obj.verify(public_key, digest, signature):
        print('Signature is correct')
    else:
        print('Signature is not correct')

.. rubric:: **Generating a public key:**

.. code-block:: python

    import gostcrypto

    private_key = bytearray.fromhex(
                  '7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019
                                            ['id-tc26-gost-3410-2012-256-paramSetB'])
    public_key = sign_obj.public_key_generate(private_key)

The 'gostrandom' module.
------------------------

Usage:
~~~~~~

.. code-block:: python

    import gostcrypto

    random_obj = gostcrypto.gostrandom.new(32)
    result = random_obj.random()

The 'gosthmac' module.
----------------------

Usage:
~~~~~~

.. rubric:: **Getting a HMAC for a string:**

.. code-block:: python

    import gostcrypto

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256')
    hmac_obj.update(b'<string>')
    result = hmac_obj.hexdigest()

.. rubric:: **Getting a HMAC for a file:**

.. code-block:: python

    import gostcrypto

    #The 'buffer_size' must be a multiple of 64
    buffer_size = 128
    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256')
    with open(<'file path'>, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hmac_obj.update(buffer)
            buffer = file.read(buffer_size)
    result = hmac_obj.hexdigest()

The 'gostpbkdf' module.
-----------------------

Usage:
~~~~~~

.. code-block:: python

    import gostcrypto

    pbkdf_obj = new(<'password'>, <'salt'>)
    result = pbkdf_obj.derive(32)
