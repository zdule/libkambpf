/*
    This file is part of the libkambpf library (https://github.com/zdule/libkambpf).
    It is file is offered under two licenses GPLv2 and Apache License Version 2.
    For more information see the LICENSE file at the root of the library.

    Copyright 2020 Dusan Zivanovic
*/

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

static int list_buffer_pages_needed(int num_entries) {
    int page_size = getpagesize();
    // one extra page is added to account for the header which is up to one page.
    // this is not true in general, but it is true for now.
    // we would need to memory-map the device and get the offset from the header.
    return (num_entries*(sizeof(struct probe_table_entry)) +  page_size-1) / page_size + 1;
}
struct kambpf_list_buffer *kambpf_open_list_device(char *path, int max_entries) {
    struct kambpf_list_buffer *buf = (struct kambpf_list_buffer *)
        malloc(sizeof(struct kambpf_list_buffer));

    if (!buf) {
        fprintf(stderr, "Could not allocate a list buffer\n");
        goto erralloc;
    }

    int fd_list = open(path, O_RDONLY);
    if (fd_list < 0) {
        perror("Opening list_dev failed");
        goto erropen;
    }

    buf->pages = list_buffer_pages_needed(max_entries);
    void *list_start = mmap(0, buf->pages*getpagesize(), PROT_READ, MAP_SHARED, fd_list, 0);
    if (list_start == MAP_FAILED) {
        perror("mmaping list_dev failed");
        goto errmap;
    }

    buf->fd = fd_list;
    buf->header = (struct probe_table_header *) list_start;
    buf->entries = (struct probe_table_entry *) (list_start + buf->header->start_offset);
    //printf("%p %p %u\n", buf->header, buf->entries, buf->header->start_offset);
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

static int update_buffer_pages_needed(int num_entries) {
    int page_size = getpagesize();
    return (num_entries*(sizeof(struct kambpf_update_entry)) +  page_size-1) / page_size;
}

struct kambpf_updates_buffer *kambpf_open_updates_device(char *path, int max_entries) {
    struct kambpf_updates_buffer *buf = (struct kambpf_updates_buffer *)
        malloc(sizeof(struct kambpf_updates_buffer));

    if (!buf) {
        goto erralloc;
    }

    int fd_update = open(path, O_RDWR);
    if (fd_update < 0) {
        fprintf(stderr,"Unable to open update_dev at %s\n",path);
        perror("Opening update_dev failed");
        goto erropen;
    }

    buf->pages = update_buffer_pages_needed(max_entries);
    void *update_start = mmap(0, buf->pages*getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd_update, 0);
    if (update_start == MAP_FAILED) {
        perror("mmaping update_dev failed");
        goto errmap;
    }

    buf->fd = fd_update;
    buf->max_entries = buf->pages*getpagesize()/(sizeof(struct kambpf_update_entry));
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

#define return_if_err(expr) \
    do { \
        int check_err = (expr); \
        if (check_err) return check_err; \
    } while(0)

#define void_ret_if_err(expr) \
    do { \
        if (expr) return; \
    } while(0)


int check_updates_buffer(struct kambpf_updates_buffer *buf) {
    if (!buf) {
        fprintf(stderr, "Trying to sumbit updates to a NULL buffer\n");
        maybe_quit();
        return -EINVAL;
    }
    return 0;
}

int check_has_enough_entries(struct kambpf_updates_buffer *buf, int num) {
    if (buf->max_entries < num) {
        fprintf(stderr, "Not enough entries in the updates buffer, have %d required %d\n", buf->max_entries, num);
        maybe_quit();
        return -EINVAL;
    }
    return 0;
}

long kambpf_submit_updates(struct kambpf_updates_buffer *buf, unsigned long num) {
    return_if_err(check_updates_buffer(buf));
    return_if_err(check_has_enough_entries(buf,num));
    //printf("Submitting %lu updates\n",num);
    return ioctl(buf->fd, IOCTL_MAGIC, (unsigned long) num);
}

int kambpf_updates_set_entry(struct kambpf_updates_buffer *buf, uint32_t pos, uint64_t addr, int fd, int ret_fd) {
    return_if_err(check_updates_buffer(buf));
    return_if_err(check_has_enough_entries(buf,pos+1));
    buf->update_entries[pos].instruction_address = addr;
    buf->update_entries[pos].bpf_program_fd = fd;
    buf->update_entries[pos].bpf_return_program_fd = ret_fd;
	return 0;
}

int kambpf_updates_get_id(struct kambpf_updates_buffer *buf, uint32_t pos) {
    return_if_err(check_updates_buffer(buf));
    return_if_err(check_has_enough_entries(buf,pos+1));
    //printf("Return value %d\n",buf->update_entries[pos].table_pos);
    return buf->update_entries[pos].table_pos;
}

uint32_t kambpf_add_return_probe(struct kambpf_updates_buffer *buf, uint64_t addr, int fd, int ret_fd) {
    return_if_err(kambpf_updates_set_entry(buf, 0, addr, fd, ret_fd));
    return_if_err(kambpf_submit_updates(buf, 1));
    return buf->update_entries[0].table_pos;
}

uint32_t kambpf_add_probe(struct kambpf_updates_buffer *buf, uint64_t addr, int fd) {
	printf("\n\n\nChecking result\n");
    return_if_err(kambpf_updates_set_entry(buf, 0, addr, fd, -1));
	printf("Checking result\n");
    return_if_err(kambpf_submit_updates(buf, 1));
    return buf->update_entries[0].table_pos;
}

int kambpf_updates_set_entry_remove(struct kambpf_updates_buffer *buf, uint32_t pos, uint32_t id) {
    return_if_err(check_updates_buffer(buf));
    return_if_err(check_has_enough_entries(buf,pos+1));
    buf->update_entries[pos].instruction_address = 0;
    buf->update_entries[pos].table_pos = id;
	return 0;
}

void kambpf_remove_probe(struct kambpf_updates_buffer *buf, uint32_t id) {
    void_ret_if_err(kambpf_updates_set_entry_remove(buf, 0, id));
    void_ret_if_err(kambpf_submit_updates(buf, 1));
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
