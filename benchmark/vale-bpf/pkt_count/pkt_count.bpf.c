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

struct ether_header {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
} __attribute__((packed));

struct ip {
	uint16_t hl:4;
	uint16_t v:4;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t csum;
	uint32_t src;
	uint32_t dst;
} __attribute__((packed));

struct ip6 {
	uint32_t ver_tc_label;
	uint16_t len;
	uint8_t next_header;
	uint8_t hop_limit;
	uint32_t src[4];
	uint32_t dst[4];
} __attribute__((packed));

EBPF_DEFINE_MAP(dropcnt, "percpu_array", sizeof(uint32_t), sizeof(long), 256, 0);

static __attribute__((always_inline)) int
parse_ipv4(void *data, uint64_t nh_off, void *data_end)
{
	struct ip *iph = data + nh_off;

	if ((void *)&iph[1] > data_end) {
		return 0;
	}

	return iph->proto;
}

static __attribute__((always_inline)) int
parse_ipv6(void *data, uint64_t nh_off, void *data_end)
{
	struct ip6 *ip6h = data + nh_off;

	if ((void *)&ip6h[1] > data_end) {
		return 0;
	}

	return ip6h->next_header;
}

uint32_t
pkt_count(struct vale_bpf_md *md)
{
	void *data_end = (void *)(long)md->data_end;
	void *data = (void *)(long)md->data;

	struct ether_header *eth = data;

	long *value;
	uint16_t h_proto;
	uint64_t nh_off = 0;
	uint32_t index;

	nh_off = sizeof(*eth);

	if (data + nh_off > data_end) {
		return VALE_BPF_DROP;
	}

	h_proto = eth->type;

	if (h_proto == 0x0008) {
		index = parse_ipv4(data, nh_off, data_end);
	} else if (h_proto == 0xDD86) {
		index = parse_ipv6(data, nh_off, data_end);
	} else {
		index = 0;
	}

	value = ebpf_map_lookup_elem(&dropcnt, &index);
	if (value) {
		*value += 1;
	}

	return VALE_BPF_DROP;
}
