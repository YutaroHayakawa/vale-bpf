#ifndef _VALE_BPF_EXTERN_FUNC_
#define _VALE_BPF_EXTERN_FUNC_

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/smp.h>

#include <vale_bpf_kern.h>


/*
 * This file defines several external functions for
 * our eBPF VM. If you would like to add new external
 * function, please edit this file and
 * include/vale_bpf_extern_func.h
 */


/*
 * Structure for storing metadata such as
 * packet length and source port. This information
 * will be refered from inside of the eBPF context.
 */
struct vale_bpf_metadata {
  uint16_t pkt_len;
  uint8_t src_port;
};

/* metadata should be prepared for each cores */
static struct vale_bpf_metadata *vale_bpf_meta;

static uint16_t get_pkt_len(void) {
  unsigned int me = smp_processor_id();
  return vale_bpf_meta[me].pkt_len;
}

static uint16_t get_src_port(void) {
  unsigned int me = smp_processor_id();
  return vale_bpf_meta[me].src_port;
}

static void vale_bpf_register_func(struct vale_bpf_vm *vm) {
  vale_bpf_register(vm, 0, "get_pkt_len", get_pkt_len);
  vale_bpf_register(vm, 1, "get_src_port", get_src_port);
}

#endif
