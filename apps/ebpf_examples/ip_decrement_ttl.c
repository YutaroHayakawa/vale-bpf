#include <vale_bpf.h>

struct eth {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t type;
};

uint8_t mylookup(uint8_t *buf) {
  struct eth *eth = (struct eth *)buf;
  /* if ethernet type != IPv4, drop it */
  if (eth->type != 0x0008) {
    return 255;
  }

  /* decrement ttl value of IPv4 header */
  uint8_t *ttl = buf + 28;
  *ttl -= 1;

  /* don't reculcurate checksum for now
   * checksum culcuration will be supported
   * in external functions
   */

  return 1;
}
