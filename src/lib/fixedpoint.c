#include "fixedpoint.h"
#include <inttypes.h>
#include <stdio.h>

#define Q 14
#define F (1 << Q)

int32_t to_int_floor(fixed_point x) { return x / F; }

int32_t to_int_round(fixed_point x) {
  if (x >= 0) {
    return (x + (F / 2)) / F;
  } else {
    return (x - (F / 2)) / F;
  }
}

fixed_point to_fixed(int32_t x) { return x * F; }

fixed_point add(fixed_point x, int n) { return x + to_fixed(n); }

fixed_point subtract(fixed_point x, int n) { return x - to_fixed(n); }

fixed_point multiply(fixed_point x, fixed_point y) {
  return ((int64_t)x) * y / F;
}

fixed_point divide(fixed_point x, fixed_point y) {
  return ((int64_t)x) * F / y;
}
