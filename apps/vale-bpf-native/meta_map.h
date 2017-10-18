#ifndef _META_MAP_H_
#define _META_MAP_H_

/*
 * meta_map
 *
 * You MUST define this map when you use vale-bpf-native.
 *
 * Some metadata given by vale-bpf-native is stored in this map.
 *
 * index        data                  description
 * 0            source port           VALE port number which packet comes from
 *
 */
BPF_TABLE("percpu_array", uint32_t, uint32_t, meta_map, 256);

enum meta_map_idx {
  META_MAP_SRCPORT = 0
};

/* helper function for getting source port */
static inline uint32_t *get_sport(void) {
  return meta_map.lookup(&(uint32_t){META_MAP_SRCPORT});
}

#endif /* _META_MAP_H_ */
