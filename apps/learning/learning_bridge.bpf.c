/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2017-2018 Yutaro Hayakawa
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

#include <stdint.h>
#include <net/vale_bpf_uapi.h>

struct mac {
  uint8_t _mac[6];
} __attribute((packed));

EBPF_DEFINE_MAP(ft, HASHTABLE, sizeof(struct mac), sizeof(uint32_t), 256, 0);

uint32_t
learning_bridge(struct vale_bpf_md *md)
{
  int error;
  uint8_t *data = (uint8_t *)md->data;
  uint8_t *data_end = (uint8_t *)md->data_end;

  if (md->data_end - md->data < 14) {
    return VALE_BPF_DROP;
  }

  if (((data[6] & 1) == 0)) {
    error = ebpf_map_update_elem(&ft, (struct mac *)(data + 6),
        &md->ingress_port, EBPF_ANY);
    if (error) {
      return VALE_BPF_DROP;
    }
  }

  uint32_t *dport;
  if ((data[0] & 1) == 0) {
    dport = ebpf_map_lookup_elem(&ft, (struct mac *)data, 0);
    if (dport) {
      return *dport;
    }
  }

  return VALE_BPF_BROADCAST;
}
