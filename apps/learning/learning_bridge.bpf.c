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
#include <sys/ebpf_uapi.h>
#include <net/vale_bpf_uapi.h>

DEFINE_MAP(ft, HASHTABLE, sizeof(uint64_t), sizeof(uint32_t), 256, 0);

// Assume little endian
#define le64toh(x) __builtin_bswap64(x)

uint32_t
learning_bridge(struct vale_bpf_md *md)
{
  int error;
  uint8_t *data = (uint8_t *)md->data;
  uint8_t *data_end = (uint8_t *)md->data_end;

  if (md->data_end - md->data < 14) {
    return VALE_BPF_DROP;
  }

  uint64_t smac, dmac;
  dmac = le64toh(*(uint64_t *)(data)) & 0xffffffffffff;
  smac = le64toh(*(uint64_t *)(data + 4));
  smac >>= 16;

  if (((data[6] & 1) == 0)) {
    error = map_update_elem(&ft, data + 6, &md->ingress_port, EBPF_ANY);
    if (error) {
      return VALE_BPF_DROP;
    }
  }

  uint32_t *dport;
  if ((data[0] & 1) == 0) {
    dport = map_lookup_elem(&ft, &dmac, 0);
    if (!dport) {
      return VALE_BPF_DROP;
    }

    return *dport;
  }

  return VALE_BPF_BROADCAST;
}
