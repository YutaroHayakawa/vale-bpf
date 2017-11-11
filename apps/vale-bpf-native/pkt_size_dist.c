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

BPF_TABLE("percpu_array", uint32_t, uint32_t, pkt_cnt, 5);

int pkt_size_dist(struct vale_bpf_md *md) {
  void *data = (void *)(long)(md->data);
  void *data_end = (void *)(long)(md->data_end);
  ptrdiff_t len = (ptrdiff_t)(data_end - data);
  uint32_t idx;
  uint32_t *val = NULL;

  if (len <= 300) {
    idx = 0;
  } else if (len < 600) {
    idx = 1;
  } else if (len < 900) {
    idx = 2;
  } else if (len < 1200) {
    idx = 3;
  } else if (len <= 1500) {
    idx = 4;
  } else {
    return VALE_BPF_DROP;
  }

  val = pkt_cnt.lookup(&idx);
  if (val) {
    *val += 1;
  }

  return VALE_BPF_DROP;
}
