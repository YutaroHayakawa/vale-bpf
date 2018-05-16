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

/*
 * Keep sync with vale_bpf.bpf.h
 */

#include <net/netmap.h>

enum vale_bpf_method {
  VALE_BPF_LOAD_PROG,
  VALE_BPF_UNLOAD_PROG
};

struct vale_bpf_req {
  uint8_t method;
  union {
    int ebpf_prog_fd;
  };
};

struct vale_bpf_md {
  uintptr_t data;
  uintptr_t data_end;
  uint32_t ingress_port;
  uint8_t ring_nr;
};

#define VALE_BPF_BROADCAST 254
#define VALE_BPF_DROP 255


/*
 * Mini library functions for loading program
 */

#ifndef _KERNEL

static int
vale_bpf_load_prog(int nmfd, const char *vale_name, int prog_fd)
{
  struct nm_ifreq nmreq;

  memset(&nmreq, 0, sizeof(nmreq));
  strcpy(nmreq.nifr_name, vale_name);

  struct vale_bpf_req *req = (struct vale_bpf_req *)nmreq.data;
  req->method = VALE_BPF_LOAD_PROG;
  req->ebpf_prog_fd = prog_fd;

  return ioctl(nmfd, NIOCCONFIG, &nmreq);
}

static int
vale_bpf_unload_prog(int nmfd, const char *vale_name)
{
  struct nm_ifreq nmreq;

  memset(&nmreq, 0, sizeof(nmreq));
  strcpy(nmreq.nifr_name, vale_name);

  struct vale_bpf_req *req = (struct vale_bpf_req *)nmreq.data;
  req->method = VALE_BPF_UNLOAD_PROG;

  return ioctl(nmfd, NIOCCONFIG, &nmreq);
}

#endif

