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

/*
 * Implementation of simple hash based L2 learning bridge.
 * This is an equivarent of VALE's default module.
 */

#include <stddef.h>
#include <stdint.h>
#include <net/vale_bpf_uapi.h>

struct hash_ent {
	uint64_t mac;
	uint64_t ports;
};

#define BUCKET_NUM	1024

#define mix(a, b, c)                                                    \
do {                                                                    \
	a -= b; a -= c; a ^= (c >> 13);                                 \
	b -= c; b -= a; b ^= (a << 8);                                  \
	c -= a; c -= b; c ^= (b >> 13);                                 \
	a -= b; a -= c; a ^= (c >> 12);                                 \
	b -= c; b -= a; b ^= (a << 16);                                 \
	c -= a; c -= b; c ^= (b >> 5);                                  \
	a -= b; a -= c; a ^= (c >> 3);                                  \
	b -= c; b -= a; b ^= (a << 10);                                 \
	c -= a; c -= b; c ^= (b >> 15);                                 \
} while (0)

static __attribute__((always_inline)) uint32_t
learning_bridge_rthash(const uint8_t *addr)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key

	b += addr[5] << 8;
	b += addr[4];
	a += addr[3] << 24;
	a += addr[2] << 16;
	a += addr[1] << 8;
	a += addr[0];

	mix(a, b, c);
	return (c & (BUCKET_NUM - 1));
}

EBPF_DEFINE_MAP(last_smac_cache, PERCPU_ARRAY, sizeof(uint32_t), sizeof(uint64_t), 1, 0);
EBPF_DEFINE_MAP(ft, PERCPU_ARRAY, sizeof(uint32_t), sizeof(struct hash_ent), BUCKET_NUM, 0);

uint32_t
learning_bridge(struct vale_bpf_md *md)
{
  uint8_t *data = (uint8_t *)md->data;
  uint8_t *data_end = (uint8_t *)md->data_end;
  uint32_t sh, dh;
  uint32_t dst, mysrc = md->ingress_port;
	struct hash_ent *ft_ent;

  if (data + 14 > data_end) {
	  return VALE_BPF_DROP;
  }

  uint64_t smac, dmac;
  dmac = (*(uint64_t *)(data)) & 0xffffffffffff;
  smac = (*(uint64_t *)(data + 4));
  smac >>= 16;

  uint64_t *last_smac;
  last_smac = ebpf_map_lookup_elem(&last_smac_cache, &(uint32_t){0});
  if (last_smac == NULL) {
		return VALE_BPF_DROP;
  }

  if (((data[6] & 1) == 0) && (*last_smac != smac)) {
		sh = learning_bridge_rthash((uint8_t *)(data + 6));

		ft_ent = ebpf_map_lookup_elem(&ft, &sh);
		if (ft_ent == NULL) {
			return VALE_BPF_DROP;
		}

		*last_smac = ft_ent->mac = smac;
		ft_ent->ports = mysrc;
  }

  dst = VALE_BPF_DROP;
  if ((data[0] & 1) == 0) {
	  dh = learning_bridge_rthash(data);
	  ft_ent = ebpf_map_lookup_elem(&ft, &dh);
	  if (ft_ent->mac == dmac) {
		  dst = ft_ent->ports;
	  }
  }

  return dst;
}
