/*
    This file is part of the libkambpf library (https://github.com/zdule/libkambpf).
    It is file is offered under two licenses GPLv2 and Apache License Version 2.
    For more information see the LICENSE file at the root of the library.

    Copyright 2020 Dusan Zivanovic
*/

#ifndef KAMBPF_H
#define KAMBPF_H

/*
   CAUTION!!
   The size of this struct must be a power of two (32bytes currently)
   in order for an array of these to always align with page boundaries.
*/

struct probe_table_entry {
    unsigned long instruciton_address;
    union {
        struct {
            void *data;
            __u64 noop[2];
        };
        struct _probe_table_empty_entry _ee;
    };
};
_Static_assert(sizeof(struct probe_table_entry) == 32,
        "The probe_table_entry struct must have a power of two size");

/* The probe_table header is contained at the start of the first page.
   After it the table entries are laid out. */

struct probe_table_header {
    unsigned long num_entries;
    unsigned long start_offset;
    unsigned long max_num_entries;
    unsigned long _pad;
};

_Static_assert(sizeof(struct probe_table_header) == sizeof(struct probe_table_entry),
        "The size of probe_table handler must be the same as the size of probe_table_entry \
        because these have to align in a page");

/*
  CAUTION!!
  The size of this struct needs to be a power of two, so that an array of these
  can fill a memory page.
  Also note that this code is not portable. It assumes x86-64 and that addresses
  are 64bit.
*/
struct kambpf_update_entry {
    __u64 instruction_address;
    __u32 bpf_program_fd;
    // Set by the module
    union {
    	__u32 table_pos;
    	__u32 bpf_return_program_fd;
    };
};

_Static_assert(sizeof(struct kambpf_update_entry) == 16, 
               "kambpf_update_entry must have a power of two size to fill pages evenly");

#define IOCTL_MAGIC 0x3D1E
#define KAMBPF_NOOP_FD -1

#endif // KAMBPF_H
