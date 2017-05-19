#include <stdint.h>

uint8_t rewrite_mac(uint8_t *buf) {
  buf[0] = 0xaa;
  return 2;
}
