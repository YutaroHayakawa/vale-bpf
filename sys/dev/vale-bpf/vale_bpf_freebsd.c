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

#include <dev/vale-bpf/vale_bpf_platform.h>

static int
vale_bpf_loader(module_t mod, int type, void *data)
{
  int error = 0;

  switch (type) {
  case MOD_LOAD:
    error = vale_bpf_init();
    break;
  case MOD_UNLOAD:
    vale_bpf_fini();
    break;
  default:
    error = -EINVAL;
  }

  return -error;
}

DEV_MODULE(vale_bpf, vale_bpf_loader, NULL);
MODULE_DEPEND(vale_bpf, netmap, 1, 1, 1);
MODULE_DEPEND(vale_bpf, ebpf, 1, 1, 1);
MODULE_DEPEND(vale_bpf, ebpf_dev, 1, 1, 1);
