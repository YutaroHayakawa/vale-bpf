#include <stdint.h>
#include <vale_bpf_extern_func.h>

#define DROP 255
#define BROAD_CAST 254

uint8_t mylookup(uint8_t *buf) {
  uint16_t len = get_pkt_len(); // get packet length;
  uint8_t sport = get_src_port(); // get packet length;

  if (len > 128) {
    return 1;
  }

  if (sport == 0) {
    return DROP;
  }

  return DROP;
}
