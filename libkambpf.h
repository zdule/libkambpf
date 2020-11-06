/*
    This file is part of the libkambpf library (https://github.com/zdule/libkambpf).
    It is file is offered under two licenses GPLv2 and Apache License Version 2.
    For more information see the LICENSE file at the root of the library.

    Copyright 2020 Dusan Zivanovic
*/

#include "kambpf_user.h"
#include <stdint.h>
#include <stdbool.h>

void set_quit_on_error(bool value);

struct kambpf_list_buffer {
    int fd;
    int pages;
    struct probe_table_header *header;
    struct probe_table_entry *entries;
};

struct kambpf_list_buffer *kambpf_open_list_device(char *path, int max_entries);
void kambpf_free_list_buffer(struct kambpf_list_buffer *buf);

struct kambpf_updates_buffer {
    int fd;
    int max_entries;
    int pages;
    struct kambpf_update_entry *update_entries;
};

struct kambpf_updates_buffer *kambpf_open_updates_device(char *path, int max_entries);
int kambpf_updates_set_entry(struct kambpf_updates_buffer *buf, uint32_t pos, uint64_t addr, int fd, int ret_fd);
int kambpf_updates_set_entry_remove(struct kambpf_updates_buffer *buf, uint32_t pos, uint32_t id);
int kambpf_updates_get_id(struct kambpf_updates_buffer *buf, uint32_t pos);
long kambpf_submit_updates(struct kambpf_updates_buffer *buf, unsigned long num);
uint32_t kambpf_add_probe(struct kambpf_updates_buffer *buf, uint64_t addr, int fd);
uint32_t kambpf_add_return_probe(struct kambpf_updates_buffer *buf, uint64_t addr, int fd, int ret_fd);
void kambpf_free_updates_buffer(struct kambpf_updates_buffer *buf);

void kambpf_remove_probe(struct kambpf_updates_buffer *buf, uint32_t pos);
