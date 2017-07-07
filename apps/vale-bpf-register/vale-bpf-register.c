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

#include <net/vale_bpf.h>

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
  int id = -1;
  char *sw_name;
  enum vale_bpf_method method = __MAX_METHOD;

  int opt;
  while ((opt = getopt(argc, argv, "rus:i:")) != -1) {
    switch (opt) {
      case 'r':
        if (method != __MAX_METHOD) {
          D("Method already specified");
          usage();
          return -1;
        }
        method = REGISTER_VM;
        break;
      case 'u':
        if (method != __MAX_METHOD) {
          D("Method already specified");
          usage();
          return -1;
        }
        method = UNREGISTER_VM;
        break;
      case 's':
        sw_name = strdup(optarg);
        break;
      case 'i':
        id = atoi(optarg);
        break;
      default:
        usage();
        return EXIT_FAILURE;
    }
  }

  if (id < 0) {
    D("Please specify id");
    return -1;
  }

  if (id > 255) {
    D("Invalid id");
    return -1;
  }

  nmfd = open("/dev/netmap", O_RDWR);
  if (nmfd < 0) {
    die("open");
  }

  struct nm_ifreq req;
  memset(&req, 0, sizeof(req));
  strcpy(req.nifr_name, sw_name);

  struct vale_bpf_req *r = (struct vale_bpf_req *)req.data;
  r->method = method;
  r->reg_data.id = (uint8_t)id;

  err = ioctl(nmfd, NIOCCONFIG, &req);
  if (err < 0) {
    die("ioctl NIOCCONFIG");
  }

  free(sw_name);
  close(nmfd);

  return 0;
}
