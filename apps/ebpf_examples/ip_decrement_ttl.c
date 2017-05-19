#include <stdbool.h>
#include <stdint.h>

uint8_t mylookup(uint8_t *buf) {
  /* if ethernet type != IPv4, drop it */
  if ((uint16_t) * (buf + 12) != 0x0008) {
    return 255;
  }

  /* decrement ttl value of IPv4 header */
  uint8_t *ttl = buf + 12;
  *ttl -= 1;

  /* don't reculcurate checksum for now */

  return 1;
}
