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
static char *vale_name = NULL;

static void
on_sigint(int sig)
{
  end = 1;
}

#define PROG_NAME "pkt_count.bpf.o"

static void
usage(void) {
	printf("Usage: ./pkt_count_loader -v <vale_name>\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
  int opt, nmfd, error;
  size_t len;

  while ((opt = getopt(argc, argv, "v:")) != -1) {
	  switch (opt) {
		case 'v':
			len = strlen(optarg);
			vale_name = malloc(len + 2);
			if (vale_name == NULL) {
				perror("malloc");
				usage();
			}
			strcpy(vale_name, optarg);
			vale_name[len] = ':';
			vale_name[len + 1] = '\0';
			break;
		default:
			usage();
	  }
  }

  if (vale_name == NULL) {
	  usage();
  }

  nmfd = open("/dev/netmap", O_RDWR);
  if (nmfd < 0) {
    perror("open /dev/netmap");
    exit(EXIT_FAILURE);
  }

  struct vale_bpf_info *info;
  info = vale_bpf_load_elf_start("./" PROG_NAME);
  if (!info) {
    printf("Failed to load " PROG_NAME "\n");
    exit(EXIT_FAILURE);
  }

  if (info->nprog == 0) {
    printf("There is no program in " PROG_NAME "\n");
    exit(EXIT_FAILURE);
  }

  int progfd = gbpf_load_prog((GBPFDriver *)info->driver,
		  EBPF_PROG_TYPE_TEST, info->progs[0].prog,
		  info->progs[0].prog_len);
  if (progfd < 0) {
	  perror("gbpf_load_prog");
	  exit(EXIT_FAILURE);
  }

  error = vale_bpf_load_prog(nmfd, vale_name, progfd);
  if (error) {
    printf("Failed to load program to %s\n", vale_name);
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, on_sigint);

  printf("Running nologic program on vale0, press Ctrl-C to finish\n");

	int ncores = sysconf(_SC_NPROCESSORS_ONLN);
	long values[ncores];
	long prev_sums[256] = {0};
  while (!end) {
	  for (uint32_t i = 0; i < 256; i++) {
		  error = gbpf_map_lookup_elem((GBPFDriver *)info->driver,
				  info->maps[0].fd, &i, values);
		  if (error) {
			  perror("gbpf_map_lookup_element");
			  exit(EXIT_FAILURE);
		  }

		  long sum = 0, tmp = 0;
		  for (int j = 0; j < ncores; j++) {
			  sum += values[j];
		  }

		  tmp = sum;
		  sum -= prev_sums[i];
		  prev_sums[i] = tmp;

		  if (sum != 0) {
			  printf("%d: %ld pkt/s\n", i, sum);
		  }
	  }

	  sleep(1);
  }

  error = vale_bpf_unload_prog(nmfd, vale_name);
  if (error) {
    printf("Failed to unload program from %s\n", vale_name);
    exit(EXIT_FAILURE);
  }

  vale_bpf_load_elf_done(info);
  close(nmfd);
  free(vale_name);

  return EXIT_SUCCESS;
}
