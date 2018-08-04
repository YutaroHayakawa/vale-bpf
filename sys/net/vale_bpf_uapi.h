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

#pragma once

#include <sys/ebpf_uapi.h>

/* Declared for future extensions */
enum vale_bpf_functions {
  __VALE_BPF_FUNCTIONS_MAX
};

struct vale_bpf_md {
  uintptr_t data;
  uintptr_t data_end;
  uint32_t ingress_port;
  uint8_t ring_nr;
};

#define VALE_BPF_BROADCAST 254
#define VALE_BPF_DROP 255
