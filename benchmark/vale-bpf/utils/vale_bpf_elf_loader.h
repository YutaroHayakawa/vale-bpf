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

struct map_entry {
  char name[256];
  int fd;
};

struct prog_entry {
  char name[256];
  struct ebpf_inst *prog;
  uint32_t prog_len;
};

#define NPROG_MAX 256
#define NMAP_MAX 256

struct vale_bpf_info {
  uint32_t nprog;
  uint32_t nmap;
  struct prog_entry progs[NPROG_MAX];
  struct map_entry maps[NPROG_MAX];
  EBPFDevDriver *driver;
};

static void
on_prog(GBPFElfWalker *walker, const char *name,
    struct ebpf_inst *prog, uint32_t prog_len)
{
  struct vale_bpf_info *info = walker->data;

  if (info->nprog == NPROG_MAX) {
    printf("Error: Too many programs\n");
    return;
  }

  if (strlen(name) > 255) {
    printf("Error: Prog name is too long\n");
    return;
  }

  strcpy(info->progs[info->nprog].name, name);

  info->progs[info->nprog].prog = calloc(1, prog_len); 
  if (info->progs[info->nprog].prog == NULL) {
	  return;
	}

  memcpy(info->progs[info->nprog].prog, prog, prog_len);
  info->progs[info->nprog].prog_len = prog_len;
  info->nprog++;
}

static void
on_map(GBPFElfWalker *walker, const char *name,
    int desc, struct ebpf_map_def *map)
{
  struct vale_bpf_info *info = walker->data;

  if (info->nmap == NMAP_MAX) {
    printf("Error: Too many maps\n");
    return;
  }

  if (strlen(name) > 255) {
    printf("Error: Map name is too long\n");
    return;
  }

  strcpy(info->maps[info->nmap].name, name);
  info->maps[info->nmap].fd = desc;
  info->nmap++;
}

static void
vale_bpf_load_elf_done(struct vale_bpf_info *info)
{
	for (uint32_t i = 0; i < info->nprog; i++) {
		if (info->progs[i].prog != NULL) {
			free(info->progs[i].prog);
		}
	}

	for (uint32_t i = 0; i < info->nmap; i++) {
		if (info->maps[i].fd > 0) {
			close(info->maps[i].fd);
		}
	}

	ebpf_dev_driver_destroy(info->driver);
}

static struct vale_bpf_info *
vale_bpf_load_elf_start(char *elf_fname)
{
  int error;
  GBPFElfWalker walker;
  struct vale_bpf_info *ret;

  ret = malloc(sizeof(struct vale_bpf_info));
  if (!ret) {
    return NULL;
  }

  memset(ret, 0, sizeof(struct vale_bpf_info));

  ret->driver = ebpf_dev_driver_create();
  if (!ret->driver) {
    free(ret);
    return NULL;
  }

  walker.on_prog = on_prog;
  walker.on_map = on_map;
  walker.data = ret;

  error = gbpf_walk_elf(&walker, (GBPFDriver *)ret->driver,
		  elf_fname);
  if (error) {
    vale_bpf_load_elf_done(ret);
    return NULL;
  }

  return ret;
}
