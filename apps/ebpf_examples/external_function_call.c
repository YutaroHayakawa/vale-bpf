#include <vale_bpf.h>
#include <vale_bpf_ext_common.h>

uint8_t mylookup(uint8_t *buf) {
  uint16_t len = get_pkt_len();    // get packet length
  uint8_t sport = get_src_port();  // get packet length
  set_pkt_len(len); // set packet length

  return VALE_BPF_DROP;
}
