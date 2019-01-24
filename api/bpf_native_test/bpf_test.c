/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bpf_test.h"
#include <linux/bpf.h>
#include <stdint.h>

/* helper functions called from eBPF programs written in C */
static void* (*bpf_map_lookup_elem)(uint64_t map, void* key) = (void*)
    BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(uint64_t map, void* key, void* value,
                                  uint64_t flags) = (void*)
    BPF_FUNC_map_update_elem;
static uint64_t (*get_socket_cookie)(struct __sk_buff* skb) = (void*)
    BPF_FUNC_get_socket_cookie;

static inline void bpf_update_stats(struct __sk_buff* skb, uint64_t map) {
  uint64_t sock_cookie = get_socket_cookie(skb);
  struct stats_value* value;
  value = bpf_map_lookup_elem(map, &sock_cookie);
  if (!value) {
    struct stats_value newValue = {};
    bpf_map_update_elem(map, &sock_cookie, &newValue, BPF_NOEXIST);
    value = bpf_map_lookup_elem(map, &sock_cookie);
  }
  if (value) {
    __sync_fetch_and_add(&value->rxPackets, 1);
    __sync_fetch_and_add(&value->rxBytes, skb->len);
  }
}

ELF_SEC(TEST_PROG_NAME)
int ingress_prog(struct __sk_buff* skb) {
  uint32_t key = 1;
  uint32_t* config = bpf_map_lookup_elem(CONFIGURATION_MAP, &key);
  if (config) {
    if (*config) {
      bpf_update_stats(skb, COOKIE_STATS_MAP_A);
    } else {
      bpf_update_stats(skb, COOKIE_STATS_MAP_B);
    }
  }
  return skb->len;
}
