#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/off_t.h"
#include "threads/thread.h"

#define STACK_GROWTH_LIMIT PHYS_BASE - ((1 << 13) * (1 << 10))

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);
bool install_page(void *upage, void *kpage, bool writable, bool is_file,
                  struct file *file, off_t ofs);
#endif /* userprog/process.h */
