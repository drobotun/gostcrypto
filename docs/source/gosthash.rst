**'gosthash'** module
=====================

The module implementing the hash calculation algorithm GOST 34.11-2012 ('Streebog'). The module includes the GOST34112012 class and the ``new`` function.

new(name)
"""""""""
    Creates a new hashing object and returns it.

.. code-block:: python

    import gostcrypto

    hash_obj = gostcrypto.gosthash.new('streebog256')

.. rubric:: **Arguments:**

- **name** - the string with the name of the hashing algorithm (``'streebog256'`` for the GOST R 34.11-2012 algorithm with the resulting hash length of 32 bytes or ``'streebog512'`` with the resulting hash length of 64 bytes.

.. rubric:: **Return:**

- New hashing object (as an instance of the GOST34112012 class).

.. rubric:: **Exceptions:**

- ValueError('unsupported hash type') - in case of invalid value ``name``.

*****

GOST34112012
""""""""""""
    Class that implements the hash calculation algorithm GOST 34.11-2012 ('Streebog').
	
Methods:
--------

update(data)
~~~~~~~~~~~~
    Update the hash object with the bytes-like object.

.. code-block:: python

    import gostcrypto

    hash_obj = gostcrypto.gosthash.new('streebog256')
    hash_string = u'Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы'.encode('cp1251')
    hash_obj.update(hash_string)

.. rubric:: **Arguments:**

- **data** - the string from which to get the hash. Repeated calls are equivalent to a single call with the concatenation of all the arguments: ``m.update(a)``; ``m.update(b)`` is equivalent to ``m.update(a+b)``.

*****

digest()
~~~~~~~~
    Returns the digest of the data passed to the ``update()`` method so far. This is a bytes object of size ``digest_size``.

.. code-block:: python

    import gostcrypto

    hash_obj = gostcrypto.gosthash.new('streebog256')
    hash_string = u'Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы'.encode('cp1251')
    hash_obj.update(hash_string)
    result = hash_obj.digest()

.. rubric:: **Return:**

- The digest value (as a byte object).

*****

hexdigest()
~~~~~~~~~~~
    Returns the hexadecimal digest of the data passed to the ``update()`` method so far. This is a double-sized string object (``digest_size * 2``).

.. code-block:: python

    import gostcrypto

    hash_obj = gostcrypto.gosthash.new('streebog256')
    hash_string = u'Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы'.encode('cp1251')
    hash_obj.update(hash_string)
    result = hash_obj.hexdigest()

.. rubric:: **Return:**

- The digest value (as a hexadecimal string).

*****

reset()
~~~~~~~
    Resets the values of all class attributes.

.. code-block:: python

    import gostcrypto

    hash_obj = gostcrypto.gosthash.new('streebog256')
    hash_string_1 = u'Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы'.encode('cp1251')
    hash_string_2 = bytearray([
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
    ])

    hash_obj.update(hash_string_1)
    result_1 = hash_obj.digest()
    hash_obj.reset()
    hash_obj.update(hash_string_2)
    result_2 = hash_obj.digest()

*****

copy()
~~~~~~
    Returns a copy ("clone") of the hash object. This can be used to efficiently compute the digests of data sharing a common initial substring.

.. code-block:: python

    import gostcrypto

    hash_obj_1 = gostcrypto.gosthash.new('streebog256')
	hash_obj_2 = hash_obj_1.copy()

*****

Attributes:
-----------

digest_size
~~~~~~~~~~~
    An integer value the size of the resulting hash in bytes. For the ``'streebog256'`` algorithm, this value is 32, for the ``'streebog512'`` algorithm, this value is 64.

.. code-block:: python

    import gostcrypto

    hash_obj = gostcrypto.gosthash.new('streebog256')
    hash_obj_digest_size = hash_obj.digest_size

*****

block_size
~~~~~~~~~~
    An integer value the internal block size of the hash algorithm in bytes. For the ``'streebog256'`` algorithm and the ``'streebog512'`` algorithm, this value is 64.

.. code-block:: python

    import gostcrypto

    hash_obj = gostcrypto.gosthash.new('streebog256')
    hash_obj_block_size = hash_obj.block_size

*****

name
~~~~
    A text string value the name of the hashing algorithm. Respectively ``'streebog256'`` or ``'streebog512'``.

.. code-block:: python

    import gostcrypto

    hash_obj = gostcrypto.gosthash.new('streebog256')
    hash_obj_name = hash_obj.name

*****

Example of use
""""""""""""""

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

.. warning:: In this case the 'buffer_size' value must be a multiple of the 'block_size' value.

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

