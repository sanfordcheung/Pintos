/* This header defines fixed-point arithmetic macros.
   '17.14' fixed-point number representation is used, wher
   there are 17 bits before the decimal point, 14 bits after
   it, and one sign bit. The argument x, n represent a fixed-point
   number and integer respectively. */
#include <stdint.h>
#define F 16384
#define INT_TO_FP(n) ((n) * F)
#define FP_TO_INT(x) ((x) / F)
#define FP_POSITIVE_TO_INT_ROUND_NEAREST(x) (((x) + F/2) / F)
#define FP_NEGATIVE_TO_INT_ROUND_NEAREST(x) (((x) - F/2) / F)
#define FP_ADD_FP(x, y) ((x) + (y))
#define FP_SUBTRACT_FP(x, y) ((x) - (y))
#define FP_ADD_INT(x, n) ((x) + ((n) * F))
#define FP_SUBTRACT_INT(x, n) ((x) - ((n) * F))
#define FP_MULTIPLY_FP(x, y) (((int64_t)x) * (y) / F)
#define FP_MULTIPLY_INT(x, n) ((x) * (n))
#define FP_DIVIDED_FP(x, y) (((int64_t)x) * F / (y))
#define FP_DIVIDED_INT(x, n) ((x) / (n))
typedef int fp_t;