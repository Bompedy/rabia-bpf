/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __KERNEL_SKEL_H__
#define __KERNEL_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#define BPF_SKEL_SUPPORTS_MAP_AUTO_ATTACH 1

struct kernel {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *output_buf;
		struct bpf_map *bss;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *xdp_hook;
	} progs;
	struct {
		struct bpf_link *xdp_hook;
	} links;
	struct kernel__bss {
		unsigned int counter;
		char __pad0[4];
		unsigned long commit_index;
		char addresses[3][6];
	} *bss;

#ifdef __cplusplus
	static inline struct kernel *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct kernel *open_and_load();
	static inline int load(struct kernel *skel);
	static inline int attach(struct kernel *skel);
	static inline void detach(struct kernel *skel);
	static inline void destroy(struct kernel *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
kernel__destroy(struct kernel *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
kernel__create_skeleton(struct kernel *obj);

static inline struct kernel *
kernel__open_opts(const struct bpf_object_open_opts *opts)
{
	struct kernel *obj;
	int err;

	obj = (struct kernel *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = kernel__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	kernel__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct kernel *
kernel__open(void)
{
	return kernel__open_opts(NULL);
}

static inline int
kernel__load(struct kernel *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct kernel *
kernel__open_and_load(void)
{
	struct kernel *obj;
	int err;

	obj = kernel__open();
	if (!obj)
		return NULL;
	err = kernel__load(obj);
	if (err) {
		kernel__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
kernel__attach(struct kernel *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
kernel__detach(struct kernel *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *kernel__elf_bytes(size_t *sz);

static inline int
kernel__create_skeleton(struct kernel *obj)
{
	struct bpf_object_skeleton *s;
	struct bpf_map_skeleton *map __attribute__((unused));
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "kernel";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 3;
	s->map_skel_sz = 24;
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt,
			sizeof(*s->maps) > 24 ? sizeof(*s->maps) : 24);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	map = (struct bpf_map_skeleton *)((char *)s->maps + 0 * s->map_skel_sz);
	map->name = "output_buf";
	map->map = &obj->maps.output_buf;

	map = (struct bpf_map_skeleton *)((char *)s->maps + 1 * s->map_skel_sz);
	map->name = "kernel.bss";
	map->map = &obj->maps.bss;
	map->mmaped = (void **)&obj->bss;

	map = (struct bpf_map_skeleton *)((char *)s->maps + 2 * s->map_skel_sz);
	map->name = "kernel.rodata";
	map->map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "xdp_hook";
	s->progs[0].prog = &obj->progs.xdp_hook;
	s->progs[0].link = &obj->links.xdp_hook;

	s->data = kernel__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *kernel__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xf0\x1b\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1e\0\
\x01\0\xb7\x07\0\0\x01\0\0\0\x61\x12\x04\0\0\0\0\0\x61\x11\0\0\0\0\0\0\x07\x01\
\0\0\x0e\0\0\0\x2d\x21\x64\0\0\0\0\0\xb7\x01\0\0\0\0\0\0\x7b\x1a\xc8\xff\0\0\0\
\0\x18\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x71\x71\0\0\0\0\0\0\x67\x01\0\0\x38\0\0\
\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\xd0\xff\0\0\0\0\x71\x71\x01\0\0\0\0\0\x67\x01\
\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\xd8\xff\0\0\0\0\x71\x71\x02\0\0\0\
\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\xe0\xff\0\0\0\0\x71\
\x71\x03\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\xe8\xff\
\0\0\0\0\x71\x71\x04\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\
\x1a\xf0\xff\0\0\0\0\x71\x71\x05\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\
\x38\0\0\0\x7b\x1a\xf8\xff\0\0\0\0\xbf\xa6\0\0\0\0\0\0\x07\x06\0\0\xc8\xff\xff\
\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x2d\0\0\0\xbf\x63\0\0\0\0\
\0\0\xb7\x04\0\0\x38\0\0\0\x85\0\0\0\xb1\0\0\0\xb7\x01\0\0\x01\0\0\0\x7b\x1a\
\xc8\xff\0\0\0\0\x71\x71\x06\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\
\0\0\x7b\x1a\xd0\xff\0\0\0\0\x71\x71\x07\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\
\x01\0\0\x38\0\0\0\x7b\x1a\xd8\xff\0\0\0\0\x71\x71\x08\0\0\0\0\0\x67\x01\0\0\
\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\xe0\xff\0\0\0\0\x71\x71\x09\0\0\0\0\0\
\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\xe8\xff\0\0\0\0\x71\x71\
\x0a\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\xf0\xff\0\0\
\0\0\x71\x71\x0b\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\
\xf8\xff\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x2d\0\0\0\xbf\
\x63\0\0\0\0\0\0\xb7\x04\0\0\x38\0\0\0\x85\0\0\0\xb1\0\0\0\x71\x71\x0c\0\0\0\0\
\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\xd0\xff\0\0\0\0\x71\x71\
\x0d\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\xd8\xff\0\0\
\0\0\x71\x71\x0e\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\
\xe0\xff\0\0\0\0\x71\x71\x0f\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\
\0\0\x7b\x1a\xe8\xff\0\0\0\0\x71\x71\x10\0\0\0\0\0\x67\x01\0\0\x38\0\0\0\xc7\
\x01\0\0\x38\0\0\0\x7b\x1a\xf0\xff\0\0\0\0\x71\x71\x11\0\0\0\0\0\x67\x01\0\0\
\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x7b\x1a\xf8\xff\0\0\0\0\xb7\x07\0\0\x02\0\0\0\
\x7b\x7a\xc8\xff\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x2d\0\
\0\0\xbf\x63\0\0\0\0\0\0\xb7\x04\0\0\x38\0\0\0\x85\0\0\0\xb1\0\0\0\xbf\x70\0\0\
\0\0\0\0\x95\0\0\0\0\0\0\0\x41\x64\x64\x72\x65\x73\x73\x65\x73\x20\x25\x64\x3a\
\x20\x25\x30\x32\x78\x3a\x25\x30\x32\x78\x3a\x25\x30\x32\x78\x3a\x25\x30\x32\
\x78\x3a\x25\x30\x32\x78\x3a\x25\x30\x32\x78\x0a\0\x47\x50\x4c\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x59\0\0\0\x05\0\x08\0\x04\0\0\0\x10\0\0\0\x16\
\0\0\0\x1d\0\0\0\x38\0\0\0\x04\0\x18\x01\x51\0\x04\x18\xb0\x02\x01\x52\0\x04\
\x28\xc8\x02\x03\x11\0\x9f\x04\xc8\x02\xc8\x04\x03\x11\x01\x9f\x04\xc8\x04\xc8\
\x06\x03\x11\x02\x9f\0\x04\x48\xf0\x02\x01\x57\x04\xf0\x02\xe0\x04\x03\x77\x06\
\x9f\x04\xe0\x04\x90\x06\x03\x77\x0c\x9f\0\x01\x11\x01\x25\x25\x13\x05\x03\x25\
\x72\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\x73\x17\x74\x17\x8c\x01\x17\0\0\x02\
\x34\0\x03\x25\x49\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x03\x24\0\x03\x25\
\x3e\x0b\x0b\x0b\0\0\x04\x2e\x01\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\
\x0b\x3b\x0b\x27\x19\x49\x13\x3f\x19\0\0\x05\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\
\x0b\x02\x18\0\0\x06\x05\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x07\x34\
\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x08\x34\0\x03\x25\x3a\x0b\x3b\
\x0b\x49\x13\0\0\x09\x0b\x01\x11\x1b\x12\x06\0\0\x0a\x0b\x01\x55\x23\0\0\x0b\
\x34\0\x02\x18\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x0c\x01\x01\x49\x13\0\0\x0d\
\x21\0\x49\x13\x37\x0b\0\0\x0e\x26\0\x49\x13\0\0\x0f\x24\0\x03\x25\x0b\x0b\x3e\
\x0b\0\0\x10\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x05\0\0\x11\x0f\0\x49\x13\0\0\
\x12\x15\x01\x49\x13\x27\x19\0\0\x13\x05\0\x49\x13\0\0\x14\x16\0\x49\x13\x03\
\x25\x3a\x0b\x3b\x0b\0\0\x15\x26\0\0\0\x16\x13\x01\x0b\x0b\x3a\x0b\x3b\x0b\0\0\
\x17\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x38\x0b\0\0\x18\x21\0\x49\x13\x37\
\x05\0\0\x19\x04\x01\x49\x13\x03\x25\x0b\x0b\x3a\x0b\x3b\x05\0\0\x1a\x28\0\x03\
\x25\x1c\x0f\0\0\x1b\x0f\0\0\0\x1c\x13\x01\x03\x25\x0b\x0b\x3a\x0b\x3b\x0b\0\0\
\x1d\x13\x01\x03\x25\x0b\x0b\x3a\x0b\x3b\x05\0\0\x1e\x0d\0\x03\x25\x49\x13\x3a\
\x0b\x3b\x05\x38\x0b\0\0\0\x51\x02\0\0\x05\0\x01\x08\0\0\0\0\x01\0\x0c\0\x01\
\x08\0\0\0\0\0\0\0\x02\x06\x58\x03\0\0\x08\0\0\0\x0c\0\0\0\x0c\0\0\0\x02\x03\
\x36\0\0\0\0\x0d\x02\xa1\0\x03\x04\x07\x04\x02\x05\x45\0\0\0\0\x0e\x02\xa1\x01\
\x03\x06\x07\x08\x04\x06\x58\x03\0\0\x01\x5a\x21\0\x17\x5f\x01\0\0\x05\x07\xb8\
\0\0\0\0\x29\x02\xa1\x02\x06\0\x24\0\x17\x07\x02\0\0\x07\x01\x26\0\x19\xac\x01\
\0\0\x08\x25\0\x18\xac\x01\0\0\x08\x2e\0\x22\xad\x01\0\0\x08\x2f\0\x2f\xb2\x01\
\0\0\x09\x07\x18\x03\0\0\x07\x02\x2c\0\x27\x5f\x01\0\0\x0a\0\x07\x03\x2d\0\x28\
\x4f\x02\0\0\x0a\x01\x0b\x02\x91\0\x22\0\x29\xf7\x01\0\0\0\0\0\0\x0c\xc4\0\0\0\
\x0d\xcd\0\0\0\x2d\0\x0e\xc9\0\0\0\x03\x08\x06\x01\x0f\x09\x08\x07\x10\x0a\xda\
\0\0\0\x02\x3e\x10\x0e\xdf\0\0\0\x11\xe4\0\0\0\x12\xfe\0\0\0\x13\x02\x01\0\0\
\x13\x07\x01\0\0\x13\x0f\x01\0\0\x13\x07\x01\0\0\0\x03\x0b\x05\x08\x11\xc4\0\0\
\0\x14\x36\0\0\0\x0c\x01\x1b\x11\x14\x01\0\0\x15\x02\x0d\x20\x01\0\0\0\x35\x02\
\xa1\x03\x0c\xc9\0\0\0\x0d\xcd\0\0\0\x04\0\x02\x0e\x37\x01\0\0\0\x0a\x02\xa1\
\x04\x16\x10\0\x07\x17\x0f\x4e\x01\0\0\0\x08\0\x17\x11\x63\x01\0\0\0\x09\x08\0\
\x11\x53\x01\0\0\x0c\x5f\x01\0\0\x0d\xcd\0\0\0\x1b\0\x03\x10\x05\x04\x11\x68\
\x01\0\0\x0c\x5f\x01\0\0\x18\xcd\0\0\0\0\x10\0\x02\x12\x80\x01\0\0\0\x10\x02\
\xa1\x05\x0c\xc9\0\0\0\x0d\xcd\0\0\0\x03\x0d\xcd\0\0\0\x06\0\x19\x36\0\0\0\x18\
\x04\x03\x4a\x15\x1a\x13\0\x1a\x14\x01\x1a\x15\x02\x1a\x16\x03\x1a\x17\x04\0\
\x1b\x11\xb2\x01\0\0\x1c\x20\x0e\x04\xa8\x17\x19\xd3\x01\0\0\x04\xa9\0\x17\x1b\
\xd3\x01\0\0\x04\xaa\x06\x17\x1c\xe3\x01\0\0\x04\xab\x0c\0\x0c\xdf\x01\0\0\x0d\
\xcd\0\0\0\x06\0\x03\x1a\x08\x01\x14\xeb\x01\0\0\x1f\x05\x19\x14\xf3\x01\0\0\
\x1e\x01\x18\x03\x1d\x07\x02\x0c\x03\x02\0\0\x0d\xcd\0\0\0\x07\0\x03\x23\x07\
\x08\x11\x0c\x02\0\0\x1d\x2b\x18\x03\x55\x15\x1e\x25\x07\x01\0\0\x03\x56\x15\0\
\x1e\x26\x07\x01\0\0\x03\x57\x15\x04\x1e\x27\x07\x01\0\0\x03\x58\x15\x08\x1e\
\x28\x07\x01\0\0\x03\x5a\x15\x0c\x1e\x29\x07\x01\0\0\x03\x5b\x15\x10\x1e\x2a\
\x07\x01\0\0\x03\x5d\x15\x14\0\x11\xc9\0\0\0\0\x24\0\0\0\x05\0\x08\0\x02\0\0\0\
\x08\0\0\0\x12\0\0\0\x04\x30\x90\x02\x04\x98\x02\xc8\x06\0\x04\x30\x90\x02\x04\
\x98\x02\xc8\x06\0\xc4\0\0\0\x05\0\0\0\0\0\0\0\x1c\0\0\0\x30\0\0\0\x4a\0\0\0\
\x52\0\0\0\x5f\0\0\0\x6c\0\0\0\x7a\0\0\0\x81\0\0\0\x86\0\0\0\x9a\0\0\0\xac\0\0\
\0\xb1\0\0\0\xb7\0\0\0\xc0\0\0\0\xcb\0\0\0\xd0\0\0\0\xd4\0\0\0\xe0\0\0\0\xea\0\
\0\0\xf6\0\0\0\xff\0\0\0\x08\x01\0\0\x0f\x01\0\0\x1c\x01\0\0\x27\x01\0\0\x2e\
\x01\0\0\x3c\x01\0\0\x45\x01\0\0\x4d\x01\0\0\x5c\x01\0\0\x62\x01\0\0\x69\x01\0\
\0\x70\x01\0\0\x79\x01\0\0\x82\x01\0\0\x95\x01\0\0\x99\x01\0\0\x9e\x01\0\0\xa7\
\x01\0\0\xb1\x01\0\0\xc1\x01\0\0\xd0\x01\0\0\xdf\x01\0\0\xe6\x01\0\0\xe8\x01\0\
\0\xf0\x01\0\0\xf4\x01\0\0\x55\x62\x75\x6e\x74\x75\x20\x63\x6c\x61\x6e\x67\x20\
\x76\x65\x72\x73\x69\x6f\x6e\x20\x31\x35\x2e\x30\x2e\x37\0\x73\x72\x63\x2f\x6b\
\x65\x72\x6e\x65\x6c\x2f\x6b\x65\x72\x6e\x65\x6c\x2e\x63\0\x2f\x6d\x6e\x74\x2f\
\x63\x2f\x55\x73\x65\x72\x73\x2f\x70\x75\x72\x70\x2f\x62\x70\x66\x2f\x62\x70\
\x66\0\x63\x6f\x75\x6e\x74\x65\x72\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\
\x6e\x74\0\x63\x6f\x6d\x6d\x69\x74\x5f\x69\x6e\x64\x65\x78\0\x75\x6e\x73\x69\
\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x5f\x5f\x5f\x66\x6d\x74\0\x63\x68\x61\
\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\
\x5f\0\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x76\x70\x72\x69\x6e\x74\x6b\0\
\x6c\x6f\x6e\x67\0\x5f\x5f\x75\x33\x32\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x6f\
\x75\x74\x70\x75\x74\x5f\x62\x75\x66\0\x74\x79\x70\x65\0\x69\x6e\x74\0\x6d\x61\
\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x61\x64\x64\x72\x65\x73\x73\x65\x73\0\
\x58\x44\x50\x5f\x41\x42\x4f\x52\x54\x45\x44\0\x58\x44\x50\x5f\x44\x52\x4f\x50\
\0\x58\x44\x50\x5f\x50\x41\x53\x53\0\x58\x44\x50\x5f\x54\x58\0\x58\x44\x50\x5f\
\x52\x45\x44\x49\x52\x45\x43\x54\0\x78\x64\x70\x5f\x61\x63\x74\x69\x6f\x6e\0\
\x68\x5f\x64\x65\x73\x74\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\
\0\x68\x5f\x73\x6f\x75\x72\x63\x65\0\x68\x5f\x70\x72\x6f\x74\x6f\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x5f\x5f\x75\x31\x36\0\x5f\x5f\
\x62\x65\x31\x36\0\x65\x74\x68\x68\x64\x72\0\x78\x64\x70\x5f\x68\x6f\x6f\x6b\0\
\x5f\x5f\x5f\x70\x61\x72\x61\x6d\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\
\x6e\x67\x20\x6c\x6f\x6e\x67\0\x63\x74\x78\0\x64\x61\x74\x61\0\x64\x61\x74\x61\
\x5f\x65\x6e\x64\0\x64\x61\x74\x61\x5f\x6d\x65\x74\x61\0\x69\x6e\x67\x72\x65\
\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x72\x78\x5f\x71\x75\x65\x75\x65\x5f\
\x69\x6e\x64\x65\x78\0\x65\x67\x72\x65\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\
\0\x78\x64\x70\x5f\x6d\x64\0\x69\0\x61\x64\x64\x72\x65\x73\x73\0\x65\x74\x68\0\
\x66\x72\x65\x73\x68\0\x44\0\0\0\x05\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x30\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x8c\x02\0\0\x8c\x02\0\0\x36\
\x02\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\
\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x1b\0\0\0\x05\0\0\0\0\0\0\x01\
\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\
\0\0\0\x04\0\0\0\0\x10\0\0\0\0\0\0\x02\0\0\x04\x10\0\0\0\x19\0\0\0\x01\0\0\0\0\
\0\0\0\x1e\0\0\0\x05\0\0\0\x40\0\0\0\x2a\0\0\0\0\0\0\x0e\x07\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\x02\x0a\0\0\0\x35\0\0\0\x06\0\0\x04\x18\0\0\0\x3c\0\0\0\x0b\0\0\0\
\0\0\0\0\x41\0\0\0\x0b\0\0\0\x20\0\0\0\x4a\0\0\0\x0b\0\0\0\x40\0\0\0\x54\0\0\0\
\x0b\0\0\0\x60\0\0\0\x64\0\0\0\x0b\0\0\0\x80\0\0\0\x73\0\0\0\x0b\0\0\0\xa0\0\0\
\0\x82\0\0\0\0\0\0\x08\x0c\0\0\0\x88\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\
\0\x01\0\0\x0d\x02\0\0\0\x95\0\0\0\x09\0\0\0\x99\0\0\0\x01\0\0\x0c\x0d\0\0\0\
\xd0\x01\0\0\0\0\0\x0e\x0c\0\0\0\x01\0\0\0\xd8\x01\0\0\0\0\0\x01\x08\0\0\0\x40\
\0\0\0\xe6\x01\0\0\0\0\0\x0e\x10\0\0\0\x01\0\0\0\xf3\x01\0\0\0\0\0\x01\x01\0\0\
\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x12\0\0\0\x04\0\0\0\x06\0\0\0\0\0\0\0\
\0\0\0\x03\0\0\0\0\x13\0\0\0\x04\0\0\0\x03\0\0\0\xf8\x01\0\0\0\0\0\x0e\x14\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\x0a\x12\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x16\0\0\0\
\x04\0\0\0\x2d\0\0\0\x02\x02\0\0\0\0\0\x0e\x17\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\
\0\0\0\0\x12\0\0\0\x04\0\0\0\x04\0\0\0\x12\x02\0\0\0\0\0\x0e\x19\0\0\0\x01\0\0\
\0\x1b\x02\0\0\x03\0\0\x0f\0\0\0\0\x0f\0\0\0\0\0\0\0\x04\0\0\0\x11\0\0\0\0\0\0\
\0\x08\0\0\0\x15\0\0\0\0\0\0\0\x12\0\0\0\x20\x02\0\0\x01\0\0\x0f\0\0\0\0\x08\0\
\0\0\0\0\0\0\x10\0\0\0\x26\x02\0\0\x01\0\0\x0f\0\0\0\0\x18\0\0\0\0\0\0\0\x2d\0\
\0\0\x2e\x02\0\0\x01\0\0\x0f\0\0\0\0\x1a\0\0\0\0\0\0\0\x04\0\0\0\0\x69\x6e\x74\
\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\
\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6f\x75\x74\
\x70\x75\x74\x5f\x62\x75\x66\0\x78\x64\x70\x5f\x6d\x64\0\x64\x61\x74\x61\0\x64\
\x61\x74\x61\x5f\x65\x6e\x64\0\x64\x61\x74\x61\x5f\x6d\x65\x74\x61\0\x69\x6e\
\x67\x72\x65\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x72\x78\x5f\x71\x75\x65\
\x75\x65\x5f\x69\x6e\x64\x65\x78\0\x65\x67\x72\x65\x73\x73\x5f\x69\x66\x69\x6e\
\x64\x65\x78\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\
\x6e\x74\0\x63\x74\x78\0\x78\x64\x70\x5f\x68\x6f\x6f\x6b\0\x78\x64\x70\0\x2f\
\x6d\x6e\x74\x2f\x63\x2f\x55\x73\x65\x72\x73\x2f\x70\x75\x72\x70\x2f\x62\x70\
\x66\x2f\x62\x70\x66\x2f\x73\x72\x63\x2f\x6b\x65\x72\x6e\x65\x6c\x2f\x6b\x65\
\x72\x6e\x65\x6c\x2e\x63\0\x69\x6e\x74\x20\x78\x64\x70\x5f\x68\x6f\x6f\x6b\x28\
\x73\x74\x72\x75\x63\x74\x20\x78\x64\x70\x5f\x6d\x64\x20\x2a\x63\x74\x78\x29\
\x20\x7b\0\x20\x20\x20\x20\x76\x6f\x69\x64\x20\x2a\x64\x61\x74\x61\x5f\x65\x6e\
\x64\x20\x3d\x20\x28\x76\x6f\x69\x64\x20\x2a\x29\x20\x28\x6c\x6f\x6e\x67\x29\
\x20\x63\x74\x78\x2d\x3e\x64\x61\x74\x61\x5f\x65\x6e\x64\x3b\0\x20\x20\x20\x20\
\x76\x6f\x69\x64\x20\x2a\x64\x61\x74\x61\x20\x3d\x20\x28\x76\x6f\x69\x64\x20\
\x2a\x29\x20\x28\x6c\x6f\x6e\x67\x29\x20\x63\x74\x78\x2d\x3e\x64\x61\x74\x61\
\x3b\0\x20\x20\x20\x20\x69\x66\x20\x28\x64\x61\x74\x61\x20\x2b\x20\x73\x69\x7a\
\x65\x6f\x66\x28\x73\x74\x72\x75\x63\x74\x20\x65\x74\x68\x68\x64\x72\x29\x20\
\x3e\x20\x64\x61\x74\x61\x5f\x65\x6e\x64\x29\x20\x7b\0\x20\x20\x20\x20\x20\x20\
\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x41\x64\x64\x72\x65\
\x73\x73\x65\x73\x20\x25\x64\x3a\x20\x25\x30\x32\x78\x3a\x25\x30\x32\x78\x3a\
\x25\x30\x32\x78\x3a\x25\x30\x32\x78\x3a\x25\x30\x32\x78\x3a\x25\x30\x32\x78\
\x5c\x6e\x22\x2c\0\x7d\0\x63\x6f\x75\x6e\x74\x65\x72\0\x75\x6e\x73\x69\x67\x6e\
\x65\x64\x20\x6c\x6f\x6e\x67\0\x63\x6f\x6d\x6d\x69\x74\x5f\x69\x6e\x64\x65\x78\
\0\x63\x68\x61\x72\0\x61\x64\x64\x72\x65\x73\x73\x65\x73\0\x78\x64\x70\x5f\x68\
\x6f\x6f\x6b\x2e\x5f\x5f\x5f\x66\x6d\x74\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\
\x2e\x62\x73\x73\0\x2e\x6d\x61\x70\x73\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\
\x63\x65\x6e\x73\x65\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\
\x9c\0\0\0\xb0\0\0\0\0\0\0\0\x08\0\0\0\xa2\0\0\0\x01\0\0\0\0\0\0\0\x0e\0\0\0\
\x10\0\0\0\xa2\0\0\0\x09\0\0\0\0\0\0\0\xa6\0\0\0\xd4\0\0\0\0\x5c\0\0\x08\0\0\0\
\xa6\0\0\0\xf7\0\0\0\x2b\x64\0\0\x10\0\0\0\xa6\0\0\0\x2b\x01\0\0\x27\x60\0\0\
\x18\0\0\0\xa6\0\0\0\x57\x01\0\0\x0e\x70\0\0\x20\0\0\0\xa6\0\0\0\x57\x01\0\0\
\x09\x70\0\0\x30\0\0\0\xa6\0\0\0\x8a\x01\0\0\x09\xa4\0\0\x10\x01\0\0\xa6\0\0\0\
\0\0\0\0\0\0\0\0\x18\x01\0\0\xa6\0\0\0\x8a\x01\0\0\x09\xa4\0\0\x48\x03\0\0\xa6\
\0\0\0\xce\x01\0\0\x01\xc8\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\x04\0\x08\0\
\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x03\0\0\0\0\0\0\xf8\0\0\0\
\x05\0\x08\0\xac\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\0\0\0\x01\0\0\
\x01\x01\x01\x1f\x04\0\0\0\0\x1a\0\0\0\x33\0\0\0\x4a\0\0\0\x03\x01\x1f\x02\x0f\
\x05\x1e\x06\x5d\0\0\0\0\xfd\x79\x40\xb7\xe5\x7b\x6f\x50\xa6\x7d\x99\x55\xaf\
\x2e\xbc\x1d\x71\0\0\0\x01\xb8\x10\xf2\x70\x73\x3e\x10\x63\x19\xb6\x7e\xf5\x12\
\xc6\x24\x6e\x7c\0\0\0\x02\xc4\x54\x1a\xc9\xeb\x57\x75\xba\x77\x80\x51\xc9\x40\
\xb0\x3a\x18\x8e\0\0\0\x03\xfe\x48\x6c\xe1\xb0\x08\xb0\x2b\x48\x69\xd1\xc3\x95\
\x31\x68\xcc\x94\0\0\0\x03\xab\x03\x20\xda\x72\x6e\x75\xd9\x04\x81\x1c\xe3\x44\
\x97\x99\x34\x9f\0\0\0\x03\x52\xec\x79\xa3\x8e\x49\xac\x7d\x1d\xc9\xe1\x46\xba\
\x88\xa7\xb1\x04\0\0\x09\x02\0\0\0\0\0\0\0\0\x03\x16\x01\x05\x2b\x0a\x22\x05\
\x27\x1f\x05\x0e\x24\x05\x09\x06\x20\x03\x64\x20\x06\x03\x29\x20\x05\0\x06\x03\
\x57\x08\xac\x05\x09\x03\x29\x20\x03\x57\x66\x03\x29\x20\x05\x01\x06\x03\x09\
\x02\x3f\x01\x02\x02\0\x01\x01\x2f\x6d\x6e\x74\x2f\x63\x2f\x55\x73\x65\x72\x73\
\x2f\x70\x75\x72\x70\x2f\x62\x70\x66\x2f\x62\x70\x66\0\x2f\x75\x73\x72\x2f\x69\
\x6e\x63\x6c\x75\x64\x65\x2f\x61\x73\x6d\x2d\x67\x65\x6e\x65\x72\x69\x63\0\x2f\
\x75\x73\x72\x2f\x6c\x6f\x63\x61\x6c\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\x62\
\x70\x66\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\x6c\x69\x6e\x75\
\x78\0\x73\x72\x63\x2f\x6b\x65\x72\x6e\x65\x6c\x2f\x6b\x65\x72\x6e\x65\x6c\x2e\
\x63\0\x69\x6e\x74\x2d\x6c\x6c\x36\x34\x2e\x68\0\x62\x70\x66\x5f\x68\x65\x6c\
\x70\x65\x72\x5f\x64\x65\x66\x73\x2e\x68\0\x62\x70\x66\x2e\x68\0\x69\x66\x5f\
\x65\x74\x68\x65\x72\x2e\x68\0\x74\x79\x70\x65\x73\x2e\x68\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x22\x01\0\0\x04\0\xf1\xff\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4c\
\x01\0\0\0\0\x03\0\x48\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2f\0\0\0\x01\0\x06\0\0\
\0\0\0\0\0\0\0\x2d\0\0\0\0\0\0\0\0\0\0\0\x03\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x03\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0a\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x03\0\x0e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x10\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x11\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x03\0\x17\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x19\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x1b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xd6\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x58\x03\0\0\0\0\0\0\x81\0\0\0\x11\
\0\x05\0\x10\0\0\0\0\0\0\0\x12\0\0\0\0\0\0\0\xa6\0\0\0\x11\0\x05\0\0\0\0\0\0\0\
\0\0\x04\0\0\0\0\0\0\0\x01\0\0\0\x11\0\x05\0\x08\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\
\0\xf8\0\0\0\x11\0\x07\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\xed\0\0\0\x11\0\x08\
\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x38\0\0\0\0\0\0\0\x01\0\0\0\x10\0\0\0\x18\
\x01\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\x18\x02\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\
\x18\x03\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\
\x11\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\
\x1f\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x23\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\
\x27\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x0c\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x14\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x1c\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x24\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x2c\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x34\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x38\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x3c\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x40\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x44\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x48\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x4c\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x50\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x54\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x58\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x5c\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x64\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x68\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x6c\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x70\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x74\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x78\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x7c\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x80\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x84\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x88\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x8c\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x90\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x94\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x98\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\x9c\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\xa0\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\xa4\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\xa8\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\xac\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\xb0\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\xb4\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\xb8\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\xbc\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\xc0\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\
\xc4\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\x11\0\0\0\
\x10\0\0\0\0\0\0\0\x02\0\0\0\x12\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x05\0\0\0\
\x20\0\0\0\0\0\0\0\x02\0\0\0\x13\0\0\0\x28\0\0\0\0\0\0\0\x02\0\0\0\x14\0\0\0\
\x30\0\0\0\0\0\0\0\x02\0\0\0\x10\0\0\0\x38\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\
\x40\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x3c\x02\0\0\0\0\0\0\x04\0\0\0\x11\0\0\0\
\x48\x02\0\0\0\0\0\0\x04\0\0\0\x12\0\0\0\x54\x02\0\0\0\0\0\0\x04\0\0\0\x10\0\0\
\0\x6c\x02\0\0\0\0\0\0\x04\0\0\0\x14\0\0\0\x84\x02\0\0\0\0\0\0\x03\0\0\0\x05\0\
\0\0\x9c\x02\0\0\0\0\0\0\x04\0\0\0\x13\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x02\0\
\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\
\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\
\x80\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\
\xa0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xb0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\
\xc0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x0c\0\0\0\
\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\
\x26\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x2a\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\
\x2e\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x3a\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\
\x4f\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x64\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\
\x79\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x8e\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\
\xa3\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xbd\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\
\x0f\x04\x13\x14\0\x63\x6f\x6d\x6d\x69\x74\x5f\x69\x6e\x64\x65\x78\0\x2e\x64\
\x65\x62\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\x2e\x72\
\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x78\x64\x70\x5f\x68\x6f\x6f\x6b\x2e\
\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x64\x65\x62\x75\x67\x5f\x72\x6e\x67\x6c\x69\x73\
\x74\x73\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x6f\x63\x6c\x69\x73\x74\x73\0\x2e\
\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\
\x74\x73\0\x2e\x62\x73\x73\0\x2e\x6d\x61\x70\x73\0\x61\x64\x64\x72\x65\x73\x73\
\x65\x73\0\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\
\x5f\x6c\x69\x6e\x65\x5f\x73\x74\x72\0\x63\x6f\x75\x6e\x74\x65\x72\0\x2e\x72\
\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\x2e\x72\x65\x6c\x78\x64\
\x70\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x78\x64\
\x70\x5f\x68\x6f\x6f\x6b\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\
\0\x6f\x75\x74\x70\x75\x74\x5f\x62\x75\x66\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\
\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\x72\x65\x6c\
\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x6b\x65\x72\x6e\x65\x6c\x2e\
\x63\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\
\x64\x61\x74\x61\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x42\x42\x30\x5f\x32\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2b\x01\0\0\x03\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9c\x1a\0\0\0\0\0\0\x53\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1c\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xc2\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x40\0\0\0\0\0\0\0\x58\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xbe\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa8\x14\0\0\0\
\0\0\0\x40\0\0\0\0\0\0\0\x1d\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\
\0\x76\0\0\0\x08\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\x03\0\0\0\0\0\0\
\x22\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3b\x01\0\
\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\x03\0\0\0\0\0\0\x2d\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf9\0\0\0\x01\0\0\0\
\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc5\x03\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7b\0\0\0\x01\0\0\0\x03\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xd0\x03\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4f\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xe0\x03\0\0\0\0\0\0\x5d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x0e\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3d\x04\0\0\
\0\0\0\0\x6c\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xca\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa9\x05\0\0\0\0\0\0\x55\
\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc6\0\0\0\
\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x14\0\0\0\0\0\0\x60\0\0\0\0\0\
\0\0\x1d\0\0\0\x0b\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x3f\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfe\x07\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x63\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x26\x08\0\0\0\0\0\0\xc8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5f\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x48\x15\0\0\0\0\0\0\0\x03\0\0\0\0\0\0\x1d\0\0\0\x0e\0\0\0\x08\0\0\0\0\0\0\
\0\x10\0\0\0\0\0\0\0\x8b\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xee\
\x08\0\0\0\0\0\0\xfa\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\
\0\0\0\0\0\xb2\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x0a\0\0\0\0\
\0\0\x48\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xae\0\
\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x18\0\0\0\0\0\0\x80\0\0\0\
\0\0\0\0\x1d\0\0\0\x11\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x47\x01\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\x0b\0\0\0\0\0\0\xda\x04\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x43\x01\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc8\x18\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x1d\0\
\0\0\x13\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x26\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x0c\x10\0\0\0\0\0\0\xd0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x28\x19\0\0\0\0\0\0\xa0\0\0\0\0\0\0\0\x1d\0\0\0\x15\0\0\0\x08\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\x15\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xe0\x10\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x11\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc8\x19\0\
\0\0\0\0\0\x20\0\0\0\0\0\0\0\x1d\0\0\0\x17\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\
\0\0\0\x05\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\x11\0\0\0\0\0\
\0\xfc\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\x01\
\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x19\0\0\0\0\0\0\xb0\0\0\0\
\0\0\0\0\x1d\0\0\0\x19\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x96\0\0\0\x01\
\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\x12\0\0\0\0\0\0\xa7\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xdf\0\0\0\x03\x4c\xff\x6f\
\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\x98\x1a\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x1d\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x33\x01\0\0\x02\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xb0\x12\0\0\0\0\0\0\xf8\x01\0\0\0\0\0\0\x01\0\0\0\x0f\0\
\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct kernel *kernel::open(const struct bpf_object_open_opts *opts) { return kernel__open_opts(opts); }
struct kernel *kernel::open_and_load() { return kernel__open_and_load(); }
int kernel::load(struct kernel *skel) { return kernel__load(skel); }
int kernel::attach(struct kernel *skel) { return kernel__attach(skel); }
void kernel::detach(struct kernel *skel) { kernel__detach(skel); }
void kernel::destroy(struct kernel *skel) { kernel__destroy(skel); }
const void *kernel::elf_bytes(size_t *sz) { return kernel__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
kernel__assert(struct kernel *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->bss->counter) == 4, "unexpected size of 'counter'");
	_Static_assert(sizeof(s->bss->commit_index) == 8, "unexpected size of 'commit_index'");
	_Static_assert(sizeof(s->bss->addresses) == 18, "unexpected size of 'addresses'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __KERNEL_SKEL_H__ */
