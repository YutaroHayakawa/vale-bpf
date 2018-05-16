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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <sys/ebpf.h>
#include <sys/ebpf_uapi.h>
#include <sys/ebpf_inst.h>
#include <sys/ebpf_dev.h>
#include <net/vale_bpf.h>
#include <gbpf/gbpf.h>

#include "../utils/vale_bpf_elf_loader.h"

static int end = 0;

static void
on_sigint(int sig)
{
  end = 1;
}

int
main(void)
{
  int nmfd, error;

  nmfd = open("/dev/netmap", O_RDWR);
  if (nmfd < 0) {
    perror("open /dev/netmap");
    exit(EXIT_FAILURE);
  }

  struct vale_bpf_info *info;
  info = vale_bpf_load_elf("./learning_bridge.bpf.o");
  if (!info) {
    printf("Failed to load leaning_bridge.o\n");
    exit(EXIT_FAILURE);
  }

  if (info->progs[0].fd == 0) {
    printf("There is no program in learning_bridge.o\n");
    exit(EXIT_FAILURE);
  }

  error = vale_bpf_load_prog(nmfd, "vale0:", info->progs[0].fd);
  if (error) {
    printf("Failed to load program to vale0\n");
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, on_sigint);

  printf("Running learning bridge on vale0, press Ctrl-C to finish\n");
  while (!end) {
    sleep(1);
  }

  error = vale_bpf_unload_prog(nmfd, "vale0:");
  if (error) {
    printf("Failed to unload program from vale0\n");
    exit(EXIT_FAILURE);
  }

  free(info);
  close(nmfd);

  return EXIT_SUCCESS;
}
