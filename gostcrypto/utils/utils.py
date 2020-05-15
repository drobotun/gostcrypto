# pylint: disable=duplicate-code

#The GOST cryptographic functions.
#
#Author: Evgeny Drobotun (c) 2020
#License: MIT

"""
General features of the ghostcrypto package.

The module that implements auxiliary functions for the operation of the
gostcrypto module.
"""
# pylint: enable=duplicate-code


def check_value(value: bytearray, size_value: int) -> bool:
    """
    Check the correctness of the variable.

    This function checks the type ('bytes' or 'bytearray') and whether
    the size of the 'value' variable matches the 'size_value' value.

    Args:
        value: The variable that you want to check.
        saize_value: The required size of the variable.

    Returns:
        Check result.
    """
    result = True
    if (not isinstance(value, (bytes, bytearray))) or len(value) != size_value:
        result = False
    return result


def msb(value: bytearray) -> int:
    """
    Return the value of the highest digit of the number 'value'.

    Args:
        value: The number for which you want to determine the value of the
          high order.
    """
    return value[0] & 0x80


def add_xor(op_a: bytearray, op_b: bytearray) -> bytearray:
    """
    Byte-by-byte 'xor' operation for byte objects.

    Args:
        op_a: The first operand.
        op_b: The second operand.

    Returns:
        Result of the byte-by-byte 'xor' operation.
    """
    op_a = bytearray(op_a)
    op_b = bytearray(op_b)
    result_len = min(len(op_a), len(op_b))
    result = bytearray(result_len)
    for i in range(result_len):
        result[i] = op_a[i] ^ op_b[i]
    return result


def zero_fill(value: bytearray) -> bytearray:
    """
    Zeroing byte objects.

    Args:
        value: The byte object that you want to reset.

    Returns:
        Reset value.
    """
    result = b''
    if isinstance(value, (bytes, bytearray)):
        result = b'/x00' * len(value)
        result = bytearray(result)
    return result


def bytearray_to_int(value: bytearray) -> int:
    """
    Convert a 'bytearray' object to a long integer.

    Args:
        value: the 'bytearray' object to convert.

    Returns:
        Long integer value from 'bytearray' object.
    """
    return int.from_bytes(value, byteorder='big')


def int_to_bytearray(value: int, num_byte: int) -> bytearray:
    """
    Convert a long integer to a 'bytearray' object.

    Args:
        value: The long integer value to convert.
        num_byte: Number of bytes in the 'bytearray' object.

    Returns:
        The 'bytearray' object from long integer value.
    """
    return bytearray(
        [(value & (0xff << pos * 8)) >> pos * 8 for pos in range(num_byte - 1, -1, -1)]
    )


def compare(op_a: bytearray, op_b: bytearray) -> bool:
    """
    Compare two byte arrays.

    This function, in contrast to the simple comparison operation '==', is
    performed in constant time to prevent timing attacks.

    Args:
        op_a: First array to compare.
        op_b: Second array to compare.

    Returns:
        Comparison result (boolean).
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


def compare_to_zero(value: bytearray) -> bool:
    """Compare byte array with zero.

    This function, in contrast to the simple comparison operation '==', is
    performed in constant time to prevent timing attacks.

    Args:
        value: Array to compare.

    Returns:
        Comparison result (boolean).
    """
    value = bytearray(value)
    res_check = 0
    for i in enumerate(value):
        check = value[i[0]] ^ 0x00
        res_check = res_check + check
    return not res_check
