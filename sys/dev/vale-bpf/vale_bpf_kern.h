/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Modified by Yutaro Hayakawa in 2017
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

#ifndef _VALE_BPF_KERN_H_
#define _VALE_BPF_KERN_H_

#if defined(linux)
#include <linux/types.h>
#elif defined(__FreeBSD__)
#include <sys/types.h>
#else
#error Unsupported platform
#endif

struct vale_bpf_vm;
typedef uint64_t (*vale_bpf_jit_fn)(void *mem, size_t mem_len);

struct vale_bpf_vm *vale_bpf_create(void);
void vale_bpf_destroy(struct vale_bpf_vm *vm);

/*
 * Register an external function
 *
 * The immediate field of a CALL instruction is an index into an array of
 * functions registered by the user. This API associates a function with
 * an index.
 *
 * 'name' should be a string with a lifetime longer than the VM.
 *
 * Returns 0 on success, -1 on error.
 */
int vale_bpf_register(struct vale_bpf_vm *vm, unsigned int idx,
                      const char *name, void *fn);

/*
 * Load code into a VM
 *
 * This must be done before calling vale_bpf_exec or vale_bpf_compile and after
 * registering all functions.
 *
 * 'code' should point to eBPF bytecodes and 'code_len' should be the size in
 * bytes of that buffer.
 *
 * Returns 0 on success, -1 on error.
 */
int vale_bpf_load(struct vale_bpf_vm *vm, const void *code, uint32_t code_len);

/*
 * Load code from an ELF file
 *
 * This must be done before calling vale_bpf_exec or vale_bpf_compile and after
 * registering all functions.
 *
 * 'elf' should point to a copy of an ELF file in memory and 'elf_len' should
 * be the size in bytes of that buffer.
 *
 * The ELF file must be 64-bit little-endian with a single text section
 * containing the eBPF bytecodes. This is compatible with the output of
 * Clang.
 *
 * Returns 0 on success, -1 on error.
 */
int vale_bpf_load_elf(struct vale_bpf_vm *vm, const void *elf, size_t elf_len);

uint64_t vale_bpf_exec(const struct vale_bpf_vm *vm, void *mem, size_t mem_len);

#if defined(linux)
vale_bpf_jit_fn vale_bpf_compile(struct vale_bpf_vm *vm);
#endif

/* OS depended functions */
void *vale_bpf_os_malloc(size_t size);
void vale_bpf_os_free(void *mem);
u_int vale_bpf_ncpus(void);
int vale_bpf_cur_cpu(void);

#endif
