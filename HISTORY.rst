Release History
"""""""""""""""

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
