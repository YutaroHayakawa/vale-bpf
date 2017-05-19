/*
 * Copyright 2015 Big Switch Networks, Inc
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

#ifndef _VALE_BPF_INT_H_
#define _VALE_BPF_INT_H_

#include <vale_bpf_kern.h>
#include <ebpf.h>

#define MAX_INSTS 65536
#define STACK_SIZE 128

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

struct vale_bpf_vm {
    struct ebpf_inst *insts;
    uint16_t num_insts;
    vale_bpf_jit_fn jitted;
    size_t jitted_size;
    ext_func *ext_funcs;
    const char **ext_func_names;
};

unsigned int vale_bpf_lookup_registered_function(struct vale_bpf_vm *vm, const char *name);

#endif
