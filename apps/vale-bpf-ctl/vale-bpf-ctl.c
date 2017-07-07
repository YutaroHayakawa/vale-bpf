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

int load_prog(int nmfd, char *sw_name, uint8_t id, int argc, char **argv) {
  int opt, err;

  void *prog = NULL;
  size_t length = 0;
  int jit = 0;
  while ((opt = getopt(argc, argv, "p:j")) != -1) {
    switch (opt) {
      case 'p':
        prog = readfile(optarg, VALE_BPF_MAX_PROG_LEN, &length);
        break;
      case 'j':
        jit = 1;
        break;
    }
  }

  if (prog == NULL) {
    fprintf(stderr, "Please specify your eBPF program\n");
    return -1;
  }

  struct nm_ifreq req;
  memset(&req, 0, sizeof(req));
  strcpy(req.nifr_name, sw_name);

  struct vale_bpf_req *r = (struct vale_bpf_req *)req.data;
  r->method = LOAD_PROG;
  r->len = sizeof(struct vale_bpf_req);
  r->prog_data.id = id;
  r->prog_data.jit = jit;
  r->prog_data.code = prog;
  r->prog_data.code_len = length;

  err = ioctl(nmfd, NIOCCONFIG, &req);

  free(prog);

  if (err) {
    D("Failed to load eBPF program to switch %s vmid %u mode %s",
        sw_name, id, jit ? "JIT" : "Interpreter");
    return -1;
  } else {
    D("Successfully loaded eBPF program to switch %s vmid %u mode %s",
        sw_name, id, jit ? "JIT" : "Interpreter");
    return 0;
  }
}

int register_vm(int nmfd, char *sw_name, uint8_t id, int argc, char **argv) {
  int err;
  struct nm_ifreq req;
  memset(&req, 0, sizeof(req));
  strcpy(req.nifr_name, sw_name);

  struct vale_bpf_req *r = (struct vale_bpf_req *)req.data;
  r->method = REGISTER_VM;
  r->reg_data.id = id;

  err = ioctl(nmfd, NIOCCONFIG, &req);
  if (err) {
    D("Failed to register vm id %u", id);
    return -1;
  } else {
    D("Successfully registered vm id %u", id);
    return 0;
  }
}

int unregister_vm(int nmfd, char *sw_name, uint8_t id, int argc, char **argv) {
  int err;
  struct nm_ifreq req;
  memset(&req, 0, sizeof(req));
  strcpy(req.nifr_name, sw_name);

  struct vale_bpf_req *r = (struct vale_bpf_req *)req.data;
  r->method = UNREGISTER_VM;
  r->reg_data.id = id;

  err = ioctl(nmfd, NIOCCONFIG, &req);
  if (err) {
    D("Failed to unregister vm id %u", id);
    return -1;
  } else {
    D("Successfully unregistered vm id %u", id);
    return 0;
  }
}

void main_usage(char *msg) {
  fprintf(stderr, "%s", msg);
  fprintf(stderr, "Usage: vale-bpf-ctl [ method ] [ options ]\n");
}

int main(int argc, char *argv[]) {
  int (*body)(int, char*, uint8_t, int, char**);

  if (argc < 2) {
    return EXIT_FAILURE;
  }

  if (strncmp(argv[1], "load-prog", sizeof(argv[1])) == 0) {
    body = load_prog;
  } else if (strncmp(argv[1], "register-vm", sizeof(argv[1])) == 0) {
    body = register_vm;
  } else if (strncmp(argv[1], "unregister-vm", sizeof(argv[1])) == 0) {
    body = unregister_vm;
  } else {
    main_usage("Invalid method name\n");
  }

  char *cargv[argc-2];
  for (int i = 2; i < argc; i++) {
    cargv[i-2] = argv[i];
  }

  optind = 2;
  opterr = 0;

  int opt;
  int id = -1;
  char *sw_name = NULL;
  while ((opt = getopt(argc, argv, "s:i:")) != -1) {
    switch (opt) {
      case 's':
        sw_name = strdup(optarg);
        break;
      case 'i':
        id = atoi(optarg);
        break;
    }
  }

  if (id < 0) {
    main_usage("Please specify id");
    return -1;
  }

  if (id > 255) {
    main_usage("Invalid id");
    return -1;
  }

  if (sw_name == NULL) {
    main_usage("Please specify switch name");
    return -1;
  }

  int nmfd;
  nmfd = open("/dev/netmap", O_RDWR);
  if (nmfd < 0) {
    die("open");
  }

  optind = 2;

  body(nmfd, sw_name, id, argc-2, &cargv);

  close(nmfd);
  free(sw_name);
  return 0;
}
