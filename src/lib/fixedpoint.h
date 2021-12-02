#ifndef LIB_FIXED_POINT_H
#define LIB_FIXED_POINT_H

#include <stdint.h>

typedef int32_t fixed_point;

extern int32_t to_int_round(fixed_point x);

extern int32_t to_int_floor(fixed_point x);

extern fixed_point to_fixed(int32_t x);

extern fixed_point add(fixed_point x, int n);

extern fixed_point subtract(fixed_point x, int n);

extern fixed_point multiply(fixed_point x, fixed_point y);

extern fixed_point divide(fixed_point x, fixed_point y);

#endif
