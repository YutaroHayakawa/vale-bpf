#include <vale_bpf.h>
#include <vale_bpf_ext_common.h>

uint8_t lookup(uint8_t *buf, uint16_t len, uint8_t sport) {
  set_pkt_len(len);  // set packet length
  return VALE_BPF_DROP;
}
