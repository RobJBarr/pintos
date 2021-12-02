#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <hash.h>
#include <list.h>
#include <stdint.h>

#include "filesys/off_t.h"
#include "fixedpoint.h"
#include "threads/synch.h"

#define NUMBER_QUEUES PRI_MAX + 1
/* States in a thread's life cycle. */
enum thread_status {
  THREAD_RUNNING, /* Running thread. */
  THREAD_READY,   /* Not running but ready to run. */
  THREAD_BLOCKED, /* Waiting for an event to trigger. */
  THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /* Error value for tid_t. */

/* Moving average of the no. threads waiting to run */
fixed_point load_avg;

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */
#define FD_START 2     /* First FD for each status */
#define MAP_START 0

#define INVALID_STATUS                                  \
  2147483647 /* Status for threads which haven't exited \
              */

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow. See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread {
  /* Owned by thread.c. */
  tid_t tid;                 /* Thread identifier. */
  enum thread_status status; /* Thread state. */
  char name[16];             /* Name (for debugging purposes). */
  uint8_t *stack;            /* Saved stack pointer. */

  int priority;                 /* Priority. */
  int effective_priority_cache; /* Cache for calculating the effective priortiy.
                                 */
  struct list_elem allelem;     /* List element for all threads list. */

  /* Shared between thread.c and synch.c. */
  struct list_elem elem; /* List element. */

  /* Struct members relating to donations */
  struct list donors_list;   /* Sorted list of donating threads */
  struct lock *donating_for; /* The lock we are donating for. Can be NULL */
  struct list_elem donation_elem; /* list elem for donors list */

#ifdef USERPROG
  /* Owned by userprog/process.c. */
  uint32_t *pagedir;       /* Page directory. */
  struct list open_files;  /* list containing files in use by the thread. */
  struct list children;    /* List of child threads. */
  struct child_elem *duty; /* Pointer to the child duties. Can be NULL. */
  struct file
      *open_exec; /* Executable file being run by a thread. Can be NULL. */
  int next_fd;    /* Stores the next fd to give to a file being opened. */
#endif

  int nice;               /* Stores the niceness of thread */
  fixed_point recent_cpu; /* Stores the recent cpu usage of thread */

#ifdef VM
  struct hash spt;      /* Supplemental Page Table */
  struct lock spt_lock; /* Used to synchronise accesses to the SPT */
  struct hash mmap_files;
  int next_mmap_id;
#endif

  /* Owned by thread.c. */
  unsigned magic; /* Detects stack overflow. */
};

/* Lock user for the editing the duties of children. */
extern struct lock duty_lock;

/* The struct used to represent the "childhood" of a process & the "duties"
 a child process has towards its parent. This structure outlives the
 process it is associated with by being malloced. */
struct child_elem {
  struct semaphore
      *wait;        /* Semaphore used for waking up the parent, can be NULL. */
  int exit_status;  /* The status of the child if it has exited, INVALID_STATUS
                       otherwise. */
  tid_t thread_tid; /* The id of the child associated with the child_elem. */
  struct thread *t; /* Pointer to the associated thread, can be NULL.*/
  struct list_elem elem; /* List_elem to insert into the children list. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);
size_t threads_ready(void);

/* Updates the recent CPU usage and the thread priority */
void update_recent_cpu(struct thread *, void *aux);
void update_priority(struct thread *, void *aux);

/* Goes through each thread and put them in correct queue */
void schedule_queues(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func(struct thread *t, void *aux);
void thread_foreach(thread_action_func *, void *);

int thread_get_priority(void);
void invalidate_priority_cache(struct thread *);
int thread_get_effective_priority(struct thread *);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

#ifdef USERPROG
int thread_wait_for(tid_t child_tid);
#endif

#endif /* threads/thread.h */
