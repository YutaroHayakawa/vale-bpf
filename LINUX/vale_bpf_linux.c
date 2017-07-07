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

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/cpumask.h>
#include <linux/smp.h>

void *vale_bpf_os_malloc(size_t size) {
  return kmalloc(size, GFP_KERNEL);
}

void vale_bpf_os_free(void *mem) {
  kfree(mem);
}

u_int vale_bpf_os_ncpus(void) {
  return num_present_cpus();
}

int vale_bpf_os_cur_cpu(void) {
  return smp_processor_id();
}

void *vale_bpf_os_alloc_exec_mem(size_t size) {
  return __vmalloc(size, GFP_KERNEL, PAGE_KERNEL_EXEC);
}

void vale_bpf_os_free_exec_mem(void *mem, size_t size) {
  vfree(mem);
}
