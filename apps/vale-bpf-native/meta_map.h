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

#ifndef _META_MAP_H_
#define _META_MAP_H_

/*
 * meta_map
 *
 * You MUST define this map when you use vale-bpf-native.
 *
 * Some metadata given by vale-bpf-native is stored in this map.
 *
 * index        data                  description
 * 0            source port           VALE port number which packet comes from
 *
 */
BPF_TABLE("percpu_array", uint32_t, uint32_t, meta_map, 256);

enum meta_map_idx {
  META_MAP_SRCPORT = 0
};

#endif /* _META_MAP_H_ */
