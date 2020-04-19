API of the 'gostcrypto.gostsignature' module
============================================

Introduction
""""""""""""

The module implements the functions of forming and verifying an electronic digital signature in accordance with GOST R 34.10-2012. The module includes the GOST34102012 and GOSTSignatureError classes, the ``new`` function and constants.

Constants
"""""""""

- **MODE_256** - 256-bit key signing mode.
- **MODE_512** - 512-bit key signing mode.
- **CURVES_R_1323565_1_024_2019** - parameters of elliptic curves defined in accordance with recommendations R 1323565.1.024-2019. It is a dictionary with the following elements:

    - **'id-tc26-gost-3410-2012-256-paramSetB'** - parameters of the elliptic curve (set "B") for the mode with the 256-bit signature key in the canonical representation form (in the form of a dictionary with elements: ``p``-module of the elliptic curve; ``a``, ``b`` - coefficients of the elliptic curve equation; ``m`` - order of the elliptic curve point group; ``q`` - order of the cyclic subgroup of the elliptic curve point group; ``x``, ``y``-coordinates of the point on the elliptic curve).
    - **'id-tc26-gost-3410-2012-256-paramSetC'** - parameters of the elliptic curve (set "C") for the mode with the 256-bit signature key in the canonical representation form (in the form of a dictionary with elements: ``p``-module of the elliptic curve; ``a``, ``b`` - coefficients of the elliptic curve equation; ``m`` - order of the elliptic curve point group; ``q`` - order of the cyclic subgroup of the elliptic curve point group; ``x``, ``y``-coordinates of the point on the elliptic curve).
    - **'id-tc26-gost-3410-2012-256-paramSetD'** - parameters of the elliptic curve (set "D") for the mode with the 256-bit signature key in the canonical representation form (in the form of a dictionary with elements: ``p``-module of the elliptic curve; ``a``, ``b`` - coefficients of the elliptic curve equation; ``m`` - order of the elliptic curve point group; ``q`` - order of the cyclic subgroup of the elliptic curve point group; ``x``, ``y``-coordinates of the point on the elliptic curve)
    - **'id-tc26-gost-3410-12-512-paramSetA'** - parameters of the elliptic curve (set "A") for the mode with the 512-bit signature key in the canonical representation form (in the form of a dictionary with elements: ``p``-module of the elliptic curve; ``a``, ``b`` - coefficients of the elliptic curve equation; ``m`` - order of the elliptic curve point group; ``q`` - order of the cyclic subgroup of the elliptic curve point group; ``x``, ``y``-coordinates of the point on the elliptic curve)
    - **'id-tc26-gost-3410-12-512-paramSetB'** - parameters of the elliptic curve (set "B") for the mode with the 512-bit signature key in the canonical representation form (in the form of a dictionary with elements: ``p``-module of the elliptic curve; ``a``, ``b`` - coefficients of the elliptic curve equation; ``m`` - order of the elliptic curve point group; ``q`` - order of the cyclic subgroup of the elliptic curve point group; ``x``, ``y``-coordinates of the point on the elliptic curve)
    - **'id-tc26-gost-3410-2012-256-paramSetA'** - parameters of the elliptic curve (set "A") for a mode with a key signature of 256 bits in the canonical form representation in the form of twisted Edwards curves (in the form of a dictionary with elements: ``p`` - module of an elliptic curve; ``a``, ``b`` - coefficients of the equation of an elliptic curve to a canonical form; ``e``, ``d`` - coefficients of the equation of an elliptic curve in twisted Edwards curves; m is the order of the group of points of an elliptic curve; ``q`` - order of cyclic subgroup of elliptic curve points; ``x``, ``y`` - coordinates of a point on an elliptic curve to a canonical form; ``u``, ``v`` - coordinates of a point on an elliptic curve in the form of twisted Edwards curves).
    - **'id-tc26-gost-3410-2012-512-paramSetC'** - parameters of the elliptic curve (set "C") for a mode with a key signature of 512 bits in the canonical form representation in the form of twisted Edwards curves (in the form of a dictionary with elements: ``p`` - module of an elliptic curve; ``a``, ``b`` - coefficients of the equation of an elliptic curve to a canonical form; ``e``, ``d`` - coefficients of the equation of an elliptic curve in twisted Edwards curves; m is the order of the group of points of an elliptic curve; ``q`` - order of cyclic subgroup of elliptic curve points; ``x``, ``y`` - coordinates of a point on an elliptic curve to a canonical form; ``u``, ``v`` - coordinates of a point on an elliptic curve in the form of twisted Edwards curves).

.. rubric:: **Example of setting an elliptic curve in canonical form**

All parameters of the elliptic curve must be set as integers. In this case the ``bytearray_to_int`` function converts a byte array to a long integer. This function is defined in the ``utils`` module of the ``gostcrypto`` package.

.. code-block:: python

    'id-tc26-gost-3410-2012-256-paramSetB': dict(
        p=bytearray_to_int(bytearray([
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
            0x97
        ])),
        a=bytearray_to_int(bytearray([
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
            0x94
        ])),
        b=0xa6,
        m=bytearray_to_int(bytearray([
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x6c, 0x61, 0x10, 0x70, 0x99, 0x5a, 0xd1,
            0x00, 0x45, 0x84, 0x1b, 0x09, 0xb7, 0x61, 0xb8,
            0x93
        ])),
        q=bytearray_to_int(bytearray([
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x6c, 0x61, 0x10, 0x70, 0x99, 0x5a, 0xd1,
            0x00, 0x45, 0x84, 0x1b, 0x09, 0xb7, 0x61, 0xb8,
            0x93
        ])),
        x=0x01,
        y=bytearray_to_int(bytearray([
            0x00, 0x8d, 0x91, 0xe4, 0x71, 0xe0, 0x98, 0x9c,
            0xda, 0x27, 0xdf, 0x50, 0x5a, 0x45, 0x3f, 0x2b,
            0x76, 0x35, 0x29, 0x4f, 0x2d, 0xdf, 0x23, 0xe3,
            0xb1, 0x22, 0xac, 0xc9, 0x9c, 0x9e, 0x9f, 0x1e,
            0x14
        ]))
    )

.. rubric:: **Example of simultaneously setting an elliptic curve in canonical form and as twisted Edwards curves**

.. code-block:: python

    'id-tc26-gost-3410-2012-256-paramSetA': dict(
        p=bytearray_to_int(bytearray([
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
            0x97
        ])),
        a=bytearray_to_int(bytearray([
            0x00, 0xc2, 0x17, 0x3f, 0x15, 0x13, 0x98, 0x16,
            0x73, 0xaf, 0x48, 0x92, 0xc2, 0x30, 0x35, 0xa2,
            0x7c, 0xe2, 0x5e, 0x20, 0x13, 0xbf, 0x95, 0xaa,
            0x33, 0xb2, 0x2c, 0x65, 0x6f, 0x27, 0x7e, 0x73,
            0x35
        ])),
        b=bytearray_to_int(bytearray([
            0x29, 0x5f, 0x9b, 0xae, 0x74, 0x28, 0xed, 0x9c,
            0xcc, 0x20, 0xe7, 0xc3, 0x59, 0xa9, 0xd4, 0x1a,
            0x22, 0xfc, 0xcd, 0x91, 0x08, 0xe1, 0x7b, 0xf7,
            0xba, 0x93, 0x37, 0xa6, 0xf8, 0xae, 0x95, 0x13
        ])),
        e=0x01,
        d=bytearray_to_int(bytearray([
            0x06, 0x05, 0xf6, 0xb7, 0xc1, 0x83, 0xfa, 0x81,
            0x57, 0x8b, 0xc3, 0x9c, 0xfa, 0xd5, 0x18, 0x13,
            0x2b, 0x9d, 0xf6, 0x28, 0x97, 0x00, 0x9a, 0xf7,
            0xe5, 0x22, 0xc3, 0x2d, 0x6d, 0xc7, 0xbf, 0xfb
        ])),
        m=bytearray_to_int(bytearray([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x3f, 0x63, 0x37, 0x7f, 0x21, 0xed, 0x98,
            0xd7, 0x04, 0x56, 0xbd, 0x55, 0xb0, 0xd8, 0x31,
            0x9c
        ])),
        q=bytearray_to_int(bytearray([
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0f, 0xd8, 0xcd, 0xdf, 0xc8, 0x7b, 0x66, 0x35,
            0xc1, 0x15, 0xaf, 0x55, 0x6c, 0x36, 0x0c, 0x67
        ])),
        x=bytearray_to_int(bytearray([
            0x00, 0x91, 0xe3, 0x84, 0x43, 0xa5, 0xe8, 0x2c,
            0x0d, 0x88, 0x09, 0x23, 0x42, 0x57, 0x12, 0xb2,
            0xbb, 0x65, 0x8b, 0x91, 0x96, 0x93, 0x2e, 0x02,
            0xc7, 0x8b, 0x25, 0x82, 0xfe, 0x74, 0x2d, 0xaa,
            0x28
        ])),
        y=bytearray_to_int(bytearray([
            0x32, 0x87, 0x94, 0x23, 0xab, 0x1a, 0x03, 0x75,
            0x89, 0x57, 0x86, 0xc4, 0xbb, 0x46, 0xe9, 0x56,
            0x5f, 0xde, 0x0b, 0x53, 0x44, 0x76, 0x67, 0x40,
            0xaf, 0x26, 0x8a, 0xdb, 0x32, 0x32, 0x2e, 0x5c
        ])),
        u=0x0d,
        v=bytearray_to_int(bytearray([
            0x60, 0xca, 0x1e, 0x32, 0xaa, 0x47, 0x5b, 0x34,
            0x84, 0x88, 0xc3, 0x8f, 0xab, 0x07, 0x64, 0x9c,
            0xe7, 0xef, 0x8d, 0xbe, 0x87, 0xf2, 0x2e, 0x81,
            0xf9, 0x2b, 0x25, 0x92, 0xdb, 0xa3, 0x00, 0xe7
        ])),
    )

.. rubric:: **Example of setting an elliptic curve as a twisted Edwards curves**

.. code-block:: python

    'id-gost-3410-2012-256-twisted-Edwards-param': dict(
        p=bytearray_to_int(bytearray([
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
            0x97
        ])),
        e=0x01,
        d=bytearray_to_int(bytearray([
            0x06, 0x05, 0xf6, 0xb7, 0xc1, 0x83, 0xfa, 0x81,
            0x57, 0x8b, 0xc3, 0x9c, 0xfa, 0xd5, 0x18, 0x13,
            0x2b, 0x9d, 0xf6, 0x28, 0x97, 0x00, 0x9a, 0xf7,
            0xe5, 0x22, 0xc3, 0x2d, 0x6d, 0xc7, 0xbf, 0xfb
        ])),
        m=bytearray_to_int(bytearray([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x3f, 0x63, 0x37, 0x7f, 0x21, 0xed, 0x98,
            0xd7, 0x04, 0x56, 0xbd, 0x55, 0xb0, 0xd8, 0x31,
            0x9c
        ])),
        q=bytearray_to_int(bytearray([
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0f, 0xd8, 0xcd, 0xdf, 0xc8, 0x7b, 0x66, 0x35,
            0xc1, 0x15, 0xaf, 0x55, 0x6c, 0x36, 0x0c, 0x67
        ])),
        u=0x0d,
        v=bytearray_to_int(bytearray([
            0x60, 0xca, 0x1e, 0x32, 0xaa, 0x47, 0x5b, 0x34,
            0x84, 0x88, 0xc3, 0x8f, 0xab, 0x07, 0x64, 0x9c,
            0xe7, 0xef, 0x8d, 0xbe, 0x87, 0xf2, 0x2e, 0x81,
            0xf9, 0x2b, 0x25, 0x92, 0xdb, 0xa3, 0x00, 0xe7
        ])),
    )

.. note::
    It is possible to use other parameters of elliptic curves besides those defined in this module. Then these parameters must meet the requirements presented in paragraph 5.2 of GOST 34.10-2012.

*****

Functions
"""""""""

new(mode, curve)
''''''''''''''''
    Creates a new signature object and returns it .

.. code-block:: python

    import gostcrypto

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

.. rubric:: **Arguments:**

- **mode** - signature generation or verification mode (acceptable values are ``MODE_256`` or ``MODE_512``).
- **curve** - parameters of the elliptic curve.

.. rubric:: **Return:**

- New signature object (as an instance of the GOST34102012 class).

.. rubric:: **Exceptions:**

- GOSTSignatureError('unsupported signature mode') - in case of unsupported signature mode.
- GOSTSignatureError('invalid parameters of the elliptic curve') - if the elliptic curve parameters are incorrect.

*****

Classes
"""""""

GOST34102012
''''''''''''

Сlass that implements processes for creating and verifying an electronic digital signature with GOST 34.10-2012.

Methods:
--------

sign(private_key, digest, rand_k)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Creating a signature.

.. code-block:: python

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    private_key = = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
    digest = bytearray.fromhex('2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')
    rand_k = bytearray.fromhex('77105c9b20bcd3122823c8cf6fcc7b956de33814e95b7fe64fed924594dceab3')

    signature = sign_obj.sign(private_key, digest, rand_k)

.. rubric:: **Arguments:**

- **private_key** - private signature key (as a 32-byte object for ``MODE_256`` or 64-byte object for ``MODE_512``).
- **digest** - digest for which the signature is calculated (the digest should be calculated using the "streebog" algorithm for GOST 34.11-2012).
- **rand_k** - random (pseudo-random) number (as a byte object). If this argument is not passed to the function, the ``random_k`` value is generated by the function itself using ``os.urandom``.

.. rubric:: **Return:**

- Signature for provided digest (as a byte object).

.. rubric:: **Exception:**

- GOSTSignatureError('invalid private key value') - if the private key value is incorrect.
- GOSTSignatureError('invalid digest value') - if the digest value is incorrect.
- GOSTSignatureError('invalid random value') - if the random value is incorrect.

*****

verify(public_key, digest, signature)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Verify a signature.

.. code-block:: python

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    public_key = = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
    digest = bytearray.fromhex('2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')
    signature = bytearray.fromhex('41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc049301456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40')

    if sign_obj.verify(public_key, digest, signature):
        print('Signature is correct')
    else:
        print('Signature is not correct')

.. rubric:: **Arguments:**

- **public_key** - public signature key (as a byte object).
- **digest** - digest for which to be checked signature (as a byte object).
- **signature** - signature of the digest being checked (as a byte object).

.. rubric:: **Return:**

- The result of the signature verification (``True`` or ``False``).

.. rubric:: **Exception:**

- GOSTSignatureError('invalid public key value') - if the public key value is incorrect.
- GOSTSignatureError('invalid digest value') - if the digest value is incorrect.
- GOSTSignatureError('invalid random value') - if the random value is incorrect.

*****

public_key_generate(private_key)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    private_key = = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')

    public_key = sign_obj.public_key_generate(private_key)

.. rubric:: **Arguments:**

- **private_key** - private signature key (as a 32-byte object for MODE_256 or 64-byte object for MODE_512).

.. rubric:: **Return:**

- Public key (as a byte object).

.. rubric:: **Exception:**

- GOSTSignatureError('invalid private key value') - if the private key value is incorrect.

*****

GOSTSignatureError
''''''''''''''''''
    The class that implements exceptions.

.. code-block:: python

    private_key = = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
    digest = bytearray.fromhex('2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')
    rand_k = bytearray.fromhex('77105c9b20bcd3122823c8cf6fcc7b956de33814e95b7fe64fed924594dceab3')
	try:
        sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
	                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])
        signature = sign_obj.sign(private_key, digest, rand_k)
    except GOSTSignatureError as err:
	    print(err)
    else:
        print(signature)

Exception types:

- ``unsupported signature mode`` - in case of unsupported signature mode.
- ``invalid parameters of the elliptic curve`` - if the elliptic curve parameters are incorrect.
- ``invalid private key value`` - if the private key value is incorrect.
- ``invalid digest value`` - if the digest value is incorrect.
- ``invalid random value`` - if the random value is incorrect.
- ``invalid public key value`` - if the public key value is incorrect.
- ``invalid signature value`` - if the signature value is incorrect.

Example of use
""""""""""""""

Signing
'''''''

.. code-block :: python

    import gostcrypto

    private_key = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
    digest = bytearray.fromhex('2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    signature = sign_obj.sign(private_key, digest)

Verify
''''''

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
'''''''''''''''''''''''

.. code-block:: python

    private_key = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')

    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

    public_key = sign_obj.public_key_generate(private_key)
