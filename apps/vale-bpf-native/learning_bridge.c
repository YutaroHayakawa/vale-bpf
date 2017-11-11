/*
 * Copyright 2017 Yutaro Hayakawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <uapi/linux/vale_bpf_native.h>
#include "meta_map.h"

struct eth_addr {
  uint8_t addr[6];
}__attribute__((packed));

struct eth {
  struct eth_addr addr[2];
};

BPF_TABLE("lru_hash", struct eth_addr, uint32_t, addr_table, 1024);

int learning_bridge(struct vale_bpf_md *md) {
  int err;
  uint8_t ret;
  uint8_t *pkt = (uint8_t *)(long)(md->data);
  uint8_t *pkt_end = (uint8_t *)(long)(md->data_end);
  uint16_t len = (uint16_t)(pkt_end - pkt);
  uint32_t *src_port_p, *dst_port;
  uint32_t src_port;

  struct eth *e = (struct eth *)pkt;
  if ((uint8_t *)(e + 1) > pkt_end) {
    return VALE_BPF_DROP;
  }

  src_port_p = get_sport();
  if (!src_port_p) {
    return VALE_BPF_DROP;
  } else {
    /*
     * addr_table.update only accepts pointer_to_stack type
     * so we need to copy pointer_to_map_value typed value
     * to stack
     */
    src_port = *src_port_p;
  }

  err = addr_table.update(e->addr, &src_port);
  if (err < 0) {
    return VALE_BPF_DROP;
  }

  ret = VALE_BPF_BROADCAST;
  dst_port = addr_table.lookup(e->addr + 1);
  if (dst_port) {
    ret = (uint8_t)(*dst_port);
  }

  return ret;
}
