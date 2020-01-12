#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#include "libkambpf.h"

bool quit_on_errr = false;

void set_quit_on_error(bool value) {
    quit_on_errr = value;
}

void maybe_quit() {
    if (quit_on_errr) {
        exit(EXIT_FAILURE);
    }
}

struct kambpf_list_buffer *kambpf_open_list_device(char *path, int max_entries) {
    struct kambpf_list_buffer *buf = (struct kambpf_list_buffer *)
        malloc(sizeof(struct kambpf_list_buffer));

    if (!buf) {
        fprintf(stderr, "Could not allocate a list buffer\n");
        goto erralloc;
    }

    int fd_list = open(path, O_RDWR);
    if (fd_list < 0) {
        perror("Opening list_dev failed");
        goto erropen;
    }

    buf->pages = 4;
    void *list_start = mmap(0, 4*getpagesize(), PROT_READ, MAP_SHARED, fd_list, 0);
    if (list_start == MAP_FAILED) {
        perror("mmaping list_dev failed");
        goto errmap;
    }

    buf->fd = fd_list;
    buf->header = (struct probe_table_header *) list_start;
    buf->entries = (struct probe_table_entry *) (list_start + buf->header->start_offset);
    return buf;

errmap:
    close(fd_list);
erropen:
    free(buf);
erralloc:
    maybe_quit();
    return NULL;
    
}

void kambpf_free_list_buffer(struct kambpf_list_buffer *buf) {
    if (!buf) {
        return;
    }
    if (buf->header != NULL)
        munmap(buf->header, buf->pages*getpagesize());
    if (buf->fd != -1)
        close(buf->fd);
    buf->header = NULL;
    buf->fd = -1;
    free(buf);
}

struct kambpf_updates_buffer *kambpf_open_updates_device(char *path, int max_entries) {
    struct kambpf_updates_buffer *buf = (struct kambpf_updates_buffer *)
        malloc(sizeof(struct kambpf_updates_buffer));

    if (!buf) {
        goto erralloc;
    }

    int fd_update = open(path, O_RDWR);
    if (fd_update < 0) {
        perror("Opening update_dev failed");
        goto erropen;
    }

    buf->pages = 4;
    void *update_start = mmap(0, 4*getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd_update, 0);
    if (update_start == MAP_FAILED) {
        perror("mmaping update_dev failed");
        goto errmap;
    }

    buf->fd = fd_update;
    buf->max_entries = 4*getpagesize()/(sizeof(struct kambpf_update_entry));
    buf->update_entries = (struct kambpf_update_entry *) update_start;
    return buf;

errmap:
    close(fd_update);
erropen:
    free(buf);
erralloc:
    maybe_quit();
    return NULL;
}

long kambpf_submit_updates(struct kambpf_updates_buffer *buf, unsigned long num) {
    if (!buf) {
        fprintf(stderr, "Trying to sumbit updates to a NULL buffer\n");
        maybe_quit();
        return -EINVAL;
    }
    return ioctl(buf->fd, IOCTL_MAGIC, (unsigned long) num);
}

uint32_t kambpf_add_probe(struct kambpf_updates_buffer *buf, uint64_t addr, int fd) {
    if (!buf) {
        fprintf(stderr, "Trying to sumbit updates to a NULL buffer\n");
        maybe_quit();
        return -EINVAL;
    }
    if (buf->max_entries == 0) {
        fprintf(stderr, "Trying to sumbit updates to a NULL buffer\n");
        maybe_quit();
        return -EINVAL;

    }
    buf->update_entries[0].instruction_address = addr;
    buf->update_entries[0].bpf_program_fd = fd;
    buf->update_entries[0].bpf_return_program_fd = -1;
    kambpf_submit_updates(buf, 1); 
    return buf->update_entries[0].table_pos;
}

void kambpf_free_updates_buffer(struct kambpf_updates_buffer *buf) {
    if (!buf) {
        return;
    }
    if (buf->update_entries != NULL)
        munmap(buf->update_entries, buf->pages*getpagesize());
    if (buf->fd != -1)
        close(buf->fd);
    buf->update_entries = NULL;
    buf->fd = -1;
    free(buf);
}
