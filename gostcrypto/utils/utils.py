"""The module that implements auxiliary functions for the operation of the
   GOSTcrypto module.

   Author: Evgeny Drobotun (c) 2020
   License: MIT

"""

__all__ = ['msb', 'add_xor', 'zero_fill',
           'bytearray_to_int', 'int_to_bytearray',
           'compare', 'compare_to_zero']

def msb(value):
    """Returns the value of the highest digit of the number 'value'.

       Args:
          :value: The number for which you want to determine the value of the high order.
    """
    return value[-1] & 0x80

def add_xor(op_a, op_b):
    """Byte-by-byte 'xor' operation for byte objects.

       Args:
          :op_a: The first operand.
          :op_b: The second operand.

       Return:
          Result of the byte-by-byte 'xor' operation.
    """
    op_a = bytearray(op_a)
    op_b = bytearray(op_b)
    result_len = min(len(op_a), len(op_b))
    result = bytearray(result_len)
    for i in range(result_len):
        result[i] = op_a[i] ^ op_b[i]
    return result

def zero_fill(size_object):
    """Zeroing byte objects.

       Args:
          :value: The size of byte object that you want to reset.
    """
    return b'/x00' * size_object

def bytearray_to_int(value):
    """Converting a 'bytearray' object to a long integer.

       Args:
          :value: The 'bytearray' object to convert.

       Return:
          Long integer value from 'bytearray' object.
    """
    return int.from_bytes(value, byteorder='big')

def int_to_bytearray(value, num_byte):
    """Converting a long integer to a 'bytearray' object.

       Args:
          :value: The long integer value to convert.
          :num_byte: Number of bytes in the 'bytearray'object.

       Return:
          'bytearray' object from long integer value.
    """
    return bytearray([(value &\
           (0xff << pos * 8)) >> pos * 8 for pos in range(num_byte - 1, -1, -1)])

def compare(op_a, op_b):
    """Comparing two byte arrays (function is performed in a constant time).

       Args:
          :op_a: First array to compare.
          :op_b: Second array to compare.

       Return:
          Сomparison result (boolean).
    """
    op_a = bytearray(op_a)
    op_b = bytearray(op_b)
    res_check = 0
    if len(op_a) != len(op_b):
        return False
    for i in enumerate(op_a):
        check = op_a[i[0]] ^ op_b[i[0]]
        res_check = res_check + check
    return not res_check

def compare_to_zero(value):
    """Comparing byte array with zero (function is performed in a constant time).

       Args:
          :value: Aarray to compare.

       Return:
          Сomparison result (boolean).
    """
    value = bytearray(value)
    res_check = 0
    for i in enumerate(value):
        check = value[i[0]] ^ 0x00
        res_check = res_check + check
    return not res_check
