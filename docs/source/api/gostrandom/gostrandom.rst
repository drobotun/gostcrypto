API of the 'gostcrypto.gostrandom' module
=========================================

Introduction
""""""""""""

The module that implements pseudo-random sequence generation in accordance with R 1323565.1.006-2017. The module includes the ``R132356510062017`` and ``GOSTRandomError`` classes, the ``new`` function and constants.

Constants
"""""""""

- **SIZE_S_384** - the size of the initial filling (seed) is 384 bits.
- **SIZE_S_320** - the size of the initial filling (seed) is 320 bits.
- **SIZE_S_256** - the size of the initial filling (seed) is 256 bits.

.. note::
    The specified values for the initial fill size are recommended in R 1323565.1.006-2017. It is possible to use other values that meet the requirements presented out in R 1323565.1.006-2017.

Functions
"""""""""

new(rand_size, \**kwargs)
'''''''''''''''''''''''''
    Creates a new pseudo-random sequence generation object and returns it.

.. code-block:: python

    import gostcrypto

    random_k = bytearray([
        0xa8, 0xe2, 0xf9, 0x00, 0xdd, 0x4d, 0x7e, 0x24,
        0x5f, 0x09, 0x75, 0x3d, 0x01, 0xe8, 0x75, 0xfc,
        0x38, 0xf1, 0x4f, 0xf5, 0x25, 0x4c, 0x94, 0xea,
        0xdb, 0x45, 0x1e, 0x4a, 0xb6, 0x03, 0xb1, 0x47,
    ])
    random_obj = gostcrypto.gostrandom.new(64,
                                           random_k=random_k,
                                           size_s=gostcrypto.gostrandom.SIZE_S_256)

.. rubric:: **Arguments:**

- **rand_size** - size of the generated random variable (in bytes).

.. rubric:: **Keyword arguments:**

- **rand_k** - initial filling (seed). If this argument is not passed to the function, the ``os.urandom`` function is used to generate the initial filling.
- **size_s** - size of the initial filling (in bytes). The default value is ``SIZE_S_384``.

.. rubric:: **Return:**

- New pseudo-random sequence generation object (as an instance of the R132356510062017 class).

.. rubric:: **Exceptions:**

- GOSTRandomError('invalid seed value size') - in case of invalid size of  initial filling.

*****

Classes
"""""""

R132356510062017
''''''''''''''''

Class that implements pseudo-random sequence generation in accordance with R 1323565.1.006-2017.

Methods:
--------

random()
~~~~~~~~
    Generating the next value from a pseudo-random sequence.

.. code-block:: python

    import gostcrypto

    random_obj = gostcrypto.gostrandom.new(32)
    random_result = random_obj.random()

.. rubric:: **Return:**

- New random value (as a byte object).

.. rubric:: **Exception:**

- GOSTRandomError('exceeded the limit value of the counter') - when the counter limit is exceeded.
- GOSTRandomError('the seed value is zero') - if the seed value is zero.

*****

reset(rand_k)
~~~~~~~~~~~~~
    Resetting the counter and setting a new initial filling.

.. code-block:: python

    import gostcrypto

    rand_k_1 = bytearray([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ])

    rand_k_2 = bytearray([
        0xa8, 0xe2, 0xf9, 0x00, 0xdd, 0x4d, 0x7e, 0x24,
        0x5f, 0x09, 0x75, 0x3d, 0x01, 0xe8, 0x75, 0xfc,
        0x38, 0xf1, 0x4f, 0xf5, 0x25, 0x4c, 0x94, 0xea,
        0xdb, 0x45, 0x1e, 0x4a, 0xb6, 0x03, 0xb1, 0x47,
    ])

    random_obj = gostcrypto.gostrandom.new(32,
                                           rand_k=rand_k_1,
                                           size_s=gostcrypto.gostrandom.SIZE_S_256)
    random_result_1 = random_obj.random()
    random_obj.reset(rand_k_2)
    random_result_2 = random_obj.random()

.. rubric:: **Arguments:**

- **rand_k** - new initial filling (seed). If this argument is not passed to the function, the ``os.urandom`` function is used to generate the initial filling.

.. rubric:: **Exception:**

- GOSTRandomError('invalid seed value size') - in case of invalid size of  initial filling.

*****

clear()
~~~~~~~
    Clearing the counter value.

.. code-block:: python

    import gostcrypto

    random_obj = gostcrypto.gostrandom.new(32)
    random_obj.clear()

*****

GOSTRandomError
'''''''''''''''
    The class that implements exceptions.

.. code-block:: python

    import gostcrypto

    random_k = bytearray([
        0xa8, 0xe2, 0xf9, 0x00, 0xdd, 0x4d, 0x7e, 0x24,
        0x5f, 0x09, 0x75, 0x3d, 0x01, 0xe8, 0x75, 0xfc,
        0x38, 0xf1, 0x4f, 0xf5, 0x25, 0x4c, 0x94, 0xea,
        0xdb, 0x45, 0x1e, 0x4a, 0xb6, 0x03, 0xb1, 0x47,
    ])
    try:
        random_obj = gostcrypto.gostrandom.new(64,
                                               random_k=random_k,
                                               size_s=gostcrypto.gostrandom.SIZE_S_256)
        random_result = random_obj.random()
    except gostcrypto.gostrandom.GOSTRandomError as err:
        print(err)
    else:
        print(random_result.hex())

Exception types:

- ``invalid seed value`` - in case of invalid value of initial filling.
- ``exceeded the limit value of the counter`` - when the counter limit is exceeded.
- ``the seed value is zero`` - if the seed value is zero.

Example of use
""""""""""""""

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
