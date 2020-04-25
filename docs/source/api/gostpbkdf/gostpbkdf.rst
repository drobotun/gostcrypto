API of the 'gostcrypto.gostpbkdf' module
========================================

Introduction
""""""""""""

The module implementing the password-based key derivation function in accordance with R 50.1.111-2016. The module includes the ``R5011112016`` and ``GOSTPBKDFError`` classes and the ``new`` function.

Functions
"""""""""

new(password, \**kwargs)
''''''''''''''''''''''''''''
    Creates a new object for the password-based key derivation function and returns it.

.. code-block:: python

    import gostcrypto

    password = b'password'
    salt = b'salt'
	
    pbkdf_obj = gostcrypto.gostpbkdf.new(password, salt=salt, counter=2000)

.. rubric:: **Arguments:**

- **password** - password that is a character string in Unicode UTF-8 encoding.

.. rubric:: **Keyword arguments:**

- **salt** - random value. If this argument is not passed to the function, the ``os.urandom`` function is used to generate this value with the length of the generated value of 32 bytes.
- **counter** - number of iterations. The default value is 1000.

.. rubric:: **Return:**

- New object for the password-based key derivation function (as an instance of the R5011112016 class).

.. rubric:: **Exception:**

- GOSTPBKDFError(invalid password value') - if the password value is incorrect.
- GOSTPBKDFError('invalid salt value') - if the salt value is incorrect.

*****

Classes
"""""""

R5011112016
'''''''''''
    Class that implementing the calculating the password-based key derivation function in accordance with R 50.1.111-2016.

Methods:
--------

derive(dk_len)
~~~~~~~~~~~~~~
    Returns a derived key (as a byte object).

.. code-block:: python

    import gostcrypto

    password = b'password'
    salt = b'salt'
	
    pbkdf_obj = gostcrypto.gostpbkdf.new(password, salt=salt, counter=2000)
    pbkdf_result = pbkdf_obj.derive(32)

.. rubric:: **Arguments:**

- **dk_len** - Required length of the output sequence (in bytes).

.. rubric:: **Return:**

- The derived key (as a byte object).

.. rubric:: **Exception:**

- GOSTPBKDFError('invalid size of the derived key') - in case of invalid size of the derived key.

*****

hexderive(dk_len)
~~~~~~~~~~~~~~~~~
    Returns a derived key (as a hexadecimal string).

.. code-block:: python

    import gostcrypto

    password = b'password'
    salt = b'salt'
	
    pbkdf_obj = gostcrypto.gostpbkdf.new(password, salt=salt, counter=2000)
    pbkdf_result = pbkdf_obj.hexderive(32)

.. rubric:: **Arguments:**

- **dk_len** - Required length of the output sequence (in bytes).

.. rubric:: **Return:**

- The derived key (as a hexadecimal string).

.. rubric:: **Exception:**

- GOSTPBKDFError('invalid size of the derived key') - in case of invalid size of the derived key.

*****

clear()
~~~~~~~
    Сlears the password value.

.. code-block:: python

    import gostcrypto

    password = b'password'
    salt = b'salt'
	
    pbkdf_obj = gostcrypto.gostpbkdf.new(password, salt=salt, counter=2000)
    pbkdf_obj.clear()

*****

Attributes:
-----------

salt
~~~~
    The byte object containing a random value (salt). Required when generating the ``salt`` value using ``os.urandom``.

.. code-block:: python

    import gostcrypto

    password = b'password'
	
    pbkdf_obj = gostcrypto.gostpbkdf.new(password)
    salt = pbkdf_obj.salt

*****

GOSTPBKDFError
''''''''''''''
    The class that implements exceptions.

.. code-block:: python

    import gostcrypto

    password = b'password'
    salt = b'salt'
	
    try: 
        pbkdf_obj = gostcrypto.gostpbkdf.new(password, salt=salt, counter=2000)
        pbkdf_result = pbkdf_obj.hexderive(32)
    except gostcrypto.gostpbkdf.GOSTPBKDFError as err:
        print(err)
    else:
        print(pbkdf_result)

Exception types:

- ``invalid password value`` - if the password value is incorrect.
- ``invalid salt value`` - if the salt value is incorrect.
- ``invalid size of the derived key`` - if the size of the derived key is incorrect.

Example of use
""""""""""""""

.. code-block:: python

    import gostcrypto

    password = b'password'
    salt = b'salt'

    pbkdf_obj = gostcrypto.gostpbkdf.new(password, salt=salt, counter=4096)
    pbkdf_result = pbkdf_obj.derive(32)
