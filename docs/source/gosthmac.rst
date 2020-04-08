**'gosthmac'** module
=====================

The module implementing the calculating the HMAC message authentication code in accordance with R 50.1.113-2016. The module includes the R5011132016 class and the ``new`` function.

new(name, key)
""""""""""""""""""""""""""""""
    Creates a new authentication code calculation object and returns it.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)

.. rubric:: **Arguments:**

- **name** - name of the authentication code calculation mode ('HMAC_GOSTR3411_2012_256' or 'HMAC_GOSTR3411_2012_512').
- **key** - authentication key (as a byte object between 32 and 64 bytes in size).

.. rubric:: **Return:**

- New authentication code calculation object object (as an instance of the R5011132016 class).

.. rubric:: **Exceptions:**

- ValueError('unsupported mode') - in case of unsupported mode.
- ValueError('invalid key size') - in case of invalid key size.

*****

R5011132016
"""""""""""

Methods:
--------

update(data)
~~~~~~~~~~~~
    Update the HMAC object with the bytes-like object.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    data = bytearray.fromhex('0126bdb87800af214341456563780100')

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    hmac_obj.update(data)

.. rubric:: **Arguments:**

- **data** - the message for which want to calculate the authentication code. Repeated calls are equivalent to a single call with the concatenation of all the arguments: ``m.update(a)``; ``m.update(b)`` is equivalent to ``m.update(a+b)``.

*****

digest()
~~~~~~~~
    Returns the HMAC message authentication code.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    data = bytearray.fromhex('0126bdb87800af214341456563780100')

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    hmac_obj.update(data)
    hmac_result = hmac_obj.digest()

.. rubric:: **Return:**

- The HMAC message authentication code (as a byte object).

*****

hexdigest()
~~~~~~~~~~~
    Returns the HMAC message authentication code as a hexadecimal string.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    data = bytearray.fromhex('0126bdb87800af214341456563780100')

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    hmac_obj.update(data)
    hmac_result = hmac_obj.hexdigest()

.. rubric:: **Return:**

- The HMAC message authentication code (as a hexadecimal string).

*****

copy()
~~~~~~
    Returns a copy (“clone”) of the HMAC object. This can be used to efficiently compute the digests of data sharing a common initial substring.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')

    hmac_obj_1 = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    hmac_obj_2 = hmac_obj.copy()

.. rubric:: **Return:**

- The copy (“clone”) of the HMAC object.

*****

reset()
~~~~~~~
    Resets the values of all class attributes.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    data_1 = bytearray.fromhex('0126bdb87800af214341456563780100')
    data_2 = bytearray.fromhex('43414565637801000126bdb87800af21')
    	
    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    hmac_obj.update(data_1)
    hmac_result_1 = hmac_obj.hexdigest()
    hmac_obj.reset()
    hmac_obj.update(data_2)
    hmac_result_2 = hmac_obj.hexdigest()

*****

clear()
~~~~~~~
    Сlears the key value.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    hmac_obj.clear()

*****

Attributes:
-----------

digest_size
~~~~~~~~~~~
    An integer value of the size of the resulting HMAC digest in bytes.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    digest_size = hmac_obj.digest_size

*****

block_size
~~~~~~~~~~~
    An integer value the internal block size of the hash algorithm in bytes.

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    block_size = hmac_obj.block_size
	
*****

name
~~~~
    A text string is the name of the authentication code calculation algorithm (``'HMAC_GOSTR3411_2012_256'`` or ``'HMAC_GOSTR3411_2012_512'``).

.. code-block:: python

    import gostcrypto

    key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')

    hmac_obj = gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', key)
    hmac_name = hmac_obj.name

*****

Example of use
""""""""""""""

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

.. warning:: In this case the 'buffer_size' value must be a multiple of the 'block_size' value.

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
