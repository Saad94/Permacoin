/*
* The "compact" format is a representation of a whole
* number N using an unsigned 32bit number similar to a
* floating point format.
* The most significant 8 bits are the unsigned exponent of base 256.
* This exponent can be thought of as "number of bytes of N".
* The lower 23 bits are the mantissa.
* Bit number 24 (0x800000) represents the sign of N.
* N = (-1^sign) * mantissa * 256^(exponent-3)
*
* Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn().
* MPI uses the most significant bit of the first byte as sign.
* Thus 0x1234560000 is compact (0x05123456)
* and  0xc0de000000 is compact (0x0600c0de)
*
* Bitcoin only uses this "compact" format for encoding difficulty
* targets, which are unsigned 256bit quantities.  Thus, all the
* complexities of the sign bit and using base 256 are probably an
* implementation accident.
*/

/*
* BITS are numbered 1-8 in order from MSB to LSB.
* BIT 1 must be 1 for reasonable difficulty.
* BIT 2 shifts difficulty by 2 bits.
* BIT 4 can be used to shift difficulty by 1 bit.
* BITS 4-8 can be used to fine-tune difficulty.
*/ 

0x0f0fffff = 00000000000000000000000000000000000fffff000000000000000000000000
0x1f0fffff = 000fffff00000000000000000000000000000000000000000000000000000000
0x1f00ffff = 0000ffff00000000000000000000000000000000000000000000000000000000
0x1e0fffff = 00000fffff000000000000000000000000000000000000000000000000000000
0x1d0fffff = 0000000fffff0000000000000000000000000000000000000000000000000000
0x1e1fffff = 00001fffff000000000000000000000000000000000000000000000000000000
0x1f1fffff = 001fffff00000000000000000000000000000000000000000000000000000000
0x1fffffff = 007fffff00000000000000000000000000000000000000000000000000000000
0x1f7fffff = 007fffff00000000000000000000000000000000000000000000000000000000






