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
long kambpf_submit_updates(struct kambpf_updates_buffer *buf, unsigned long num);
uint32_t kambpf_add_probe(struct kambpf_updates_buffer *buf, uint64_t addr, int fd);
void kambpf_free_updates_buffer(struct kambpf_updates_buffer *buf);
