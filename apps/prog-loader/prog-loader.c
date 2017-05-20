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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define NETMAP_WITH_LIBS
#include <net/netmap.h>
#include <net/netmap_user.h>

#include <vale_bpf.h>

void die(const char *msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}

static void *readfile(const char *path, size_t maxlen, size_t *len) {
  FILE *file;
  if (!strcmp(path, "-")) {
    file = fdopen(STDIN_FILENO, "r");
  } else {
    file = fopen(path, "r");
  }

  if (file == NULL) {
    fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
    return NULL;
  }

  void *data = calloc(maxlen, 1);
  size_t offset = 0;
  size_t rv;
  while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
    offset += rv;
  }

  if (ferror(file)) {
    fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
    fclose(file);
    free(data);
    return NULL;
  }

  if (!feof(file)) {
    fprintf(stderr,
            "Failed to read %s because it is too large (max %u bytes)\n", path,
            (unsigned)maxlen);
    fclose(file);
    free(data);
    return NULL;
  }

  fclose(file);
  if (len) {
    *len = offset;
  }
  return data;
}

void usage(void) {
  fprintf(stderr,
          "Usage: [-s]witch name (terminated by :) [-p]rogram name(ebpf elf) [-j]it");
}

int main(int argc, char **argv) {
  int err;
  int nmfd;
  int jit = 0;
  char *sw_name, *prog_name;

  int opt;
  while ((opt = getopt(argc, argv, "js:p:")) != -1) {
    switch (opt) {
      case 's':
        sw_name = strdup(optarg);
        break;
      case 'p':
        prog_name = strdup(optarg);
        break;
      case 'j':
        jit = 1;
        break;
      default:
        usage();
        return EXIT_FAILURE;
    }
  }

  nmfd = open("/dev/netmap", O_RDWR);
  if (nmfd < 0) {
    die("open");
  }

  struct nm_ifreq req;
  memset(&req, 0, sizeof(req));
  strcpy(req.nifr_name, sw_name);

  size_t length;
  void *prog;
  prog = readfile(prog_name, VALE_BPF_MAX_PROG_LEN, &length);
  if (prog == NULL) {
    die("readfile");
  }

  size_t inst_count = length / 64;

  D("prog: %p length: %lu insts: %lu", prog, length, inst_count);

  struct vale_bpf_req *r = (struct vale_bpf_req *)req.data;
  r->method = LOAD_PROG;
  r->len = sizeof(struct vale_bpf_req);
  r->prog_data.jit = jit;
  r->prog_data.code = prog;
  r->prog_data.code_len = length;

  err = ioctl(nmfd, NIOCCONFIG, &req);
  if (err < 0) {
    die("ioctl NIOCCONFIG");
  }

  free(prog);
  free(sw_name);
  free(prog_name);
  close(nmfd);

  return 0;
}
