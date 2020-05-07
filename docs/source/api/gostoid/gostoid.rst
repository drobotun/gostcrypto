API of the 'gostcrypto.gostoid' module
======================================

Introduction
""""""""""""

The module implements generating identifiers for cryptographic objects. This module is used in the ``gostcipher``, ``gosthash``, ``gosthmac``, and ``gostsignature`` modules to generate the respective object identifiers. The module includes the ``ObjectIdentifier`` and ``GOSTOIDError`` classes and constants.

Constants
"""""""""

- **OBJECT_IDENTIFIER_TC26** - A set of object identifiers (OIDs) of the `Technical Committee for standardization "Cryptographic information protection" <https://tc26.ru>`_ (TC 26). For more information about object identifiers of the Technical Committee TC 26, `see here <https://tc26.ru/about/protsedury-i-reglamenty/identifikatory-obektov-oid-tekhnicheskogo-komiteta-po-standartizatsii-kriptograficheskaya-zashchita-1.html>`_.

*****

Classes
"""""""

ObjectIdentifier
''''''''''''''''

Class contains information about the object identifier. The argument for class initialization is a string containing the object identifier in the dotted representation:

.. code-block:: python

    oid_obj = ObjectIdentifier('1.2.643.7.1.1.2.3')

The ``__str__`` method of the class is redefined, so that an instance of the class returns a string with the object identifier in dotted representation.

Attributes:
-----------

name
~~~~
    Returns the names of object identifiers registered with the Technical Committee for standardization (TC 26) (defined in the ``OBJECT_IDENTIFIER_TC26`` constant). If there is no name assigned to the object identifier, an empty string is returned.

.. code-block:: python

    oid_obj = ObjectIdentifier('1.2.643.7.1.1.2.3')
    print(oid_obj.name)

*****

digit
~~~~~
    Return the object identifiers as a tuple of integers. If the object identifiers is incorrectly represented, an exception is thrown ``GOSTOIDError('invalid OID value')``.

.. code-block:: python

    oid_obj = ObjectIdentifier('1.2.643.7.1.1.2.3')
    print(oid_obj.digit)

*****

octet
~~~~~
    Return the object identifier in ASN.1 encoding.

.. code-block:: python

    oid_obj = ObjectIdentifier('1.2.643.7.1.1.2.3')
    print(oid_obj.octet)

*****

GOSTOIDError
""""""""""""
    The class that implements exceptions.

Exception types:

- ``invalid OID value`` - if the object identifiers is incorrectly represented.
- ``invalid first SID value`` - if the first SID value is incorrect.
- ``invalid second SID value`` - if the second SID value is incorrect.
