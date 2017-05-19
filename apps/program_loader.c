#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#define NETMAP_WITH_LIBS
#include <net/netmap.h>
#include <net/netmap_user.h>

#include <vale_bpf_conf.h>

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
  while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
    offset += rv;
  }

  if (ferror(file)) {
    fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
    fclose(file);
    free(data);
    return NULL;
  }

  if (!feof(file)) {
    fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
            path, (unsigned)maxlen);
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
  fprintf(stderr, "Usage: [-s]witch name (terminated by :) [-p]rogram name(ebpf elf)");
}

int main(int argc, char **argv) {
  int err;
  int nmfd;
  char *sw_name, *prog_name;

  int opt;
  while ((opt = getopt(argc, argv, "s:p:")) != -1) {
    switch (opt) {
      case 's':
        sw_name = strdup(optarg);
        break;
      case 'p':
        prog_name = strdup(optarg);
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

  D("prog: %p length: %lu", prog, length);

  struct vale_bpf_req *r = (struct vale_bpf_req *)req.data;
  r->method = LOAD_PROG;
  r->len = length;
  r->data = prog;

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
