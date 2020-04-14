Release History
"""""""""""""""

.. rubric:: 1.1.0 (15.04.2020)

- Refactoring code **gostcipher** module (changed the class structure)
- Each module has its own exception class added
- In the ``new`` function of the **gostcipher** module for MAC mode, it is now possible to pass data for MAC calculation, followed by calling the ``digest`` method without first calling the ``update`` method
- In the ``new`` function of the **gosthash** module, it is now possible to pass data for hash calculation, followed by calling the ``digest`` method without first calling the ``update`` method
- Added new exceptions for various conflict situations
- Fixed some minor bugs

.. rubric:: 1.0.0 (08.04.2020)

- First release of **'gostcrypto'**