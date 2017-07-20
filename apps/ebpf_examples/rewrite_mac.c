#include <vale_bpf.h>

uint8_t rewrite_mac(uint8_t *buf, uint16_t len, uint8_t sport) {
  buf[0] = 0xaa;  // rewrite first octet of ethernet dst field
  return 2;       // foward packet to 2nd port
}
