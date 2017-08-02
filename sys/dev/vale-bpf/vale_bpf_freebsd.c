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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/smp.h>
#include <sys/proc.h>
#include <sys/pcpu.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>

#include "vale_bpf_kern.h"

void *vale_bpf_os_malloc(size_t size) {
  return malloc(size, M_DEVBUF, M_NOWAIT | M_ZERO);
}

void vale_bpf_os_free(void *mem) {
  free(mem, M_DEVBUF);
}

u_int vale_bpf_os_ncpus(void) {
  return mp_maxid + 1;
}

int vale_bpf_os_cur_cpu(void) {
  return curthread->td_oncpu;
}

void *vale_bpf_os_alloc_exec_mem(size_t size) {
  void *ret = (void *)kmem_malloc(kernel_arena, size, M_NOWAIT);
  if (ret == NULL) {
    return NULL;
  }

  return ret;
}

void vale_bpf_os_free_exec_mem(void *mem, size_t size) {
  kmem_free(kernel_arena, (vm_offset_t)mem, size);
}
