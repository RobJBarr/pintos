#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1 /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2 /* 0: read, 1: write. */
#define PF_U 0x4 /* 0: kernel, 1: user process. */
#define STACK_MAX_BYTES                                                  \
  1 << 22 /* Maximum number of bytes that can be allocated to the stack. \
             Defined as 1 << 22 = 4MB */
void exception_init(void);
void exception_print_stats(void);

#endif /* userprog/exception.h */
