#include <stdint.h>
#include <stdbool.h>

uint8_t mylookup(uint8_t *buf) {
  buf[0] = 0xaa;
  return 1;
}
