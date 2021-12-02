#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"
#include "threads/thread.h"

#define MAX_BUFFER_LENGTH 256
#define HANDLED_SYSCALLS 15
#define ERROR -1
#define USER_VADDR_BOTTOM ((void *)0x08048000)
#define SAFE_EXIT NULL

/* Used to insert a file mapping of file descriptor,
 * struct file into a thread's file list. */
struct file_elem {
  struct list_elem elem;
  struct file *file;
  int fd;
};

/* Lock to synchronize the file system - called whenever files are used. */
extern struct lock file_lock;

void syscall_init(void);
struct file_elem *get_file_elem_from_fd(int fd, struct thread *t);
uint32_t *get_pagedir(const void *vaddr);
void sys_halt(struct intr_frame *f);
void sys_exit(struct intr_frame *f);
void sys_exec(struct intr_frame *f);
void sys_wait(struct intr_frame *f);
void sys_create(struct intr_frame *f);
void sys_remove(struct intr_frame *f);
void sys_remove(struct intr_frame *f);
void sys_open(struct intr_frame *f);
void sys_filesize(struct intr_frame *f);
void sys_read(struct intr_frame *f);
void sys_write(struct intr_frame *f);
void sys_seek(struct intr_frame *f);
void sys_tell(struct intr_frame *f);
void sys_close(struct intr_frame *f);
void sys_mmap(struct intr_frame *f);
void sys_munmap(struct intr_frame *f);

#endif /* userprog/syscall.h */
