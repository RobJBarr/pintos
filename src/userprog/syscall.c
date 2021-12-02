#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/user/syscall.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#ifdef VM
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "vm/mmap.h"
#endif

static int get_user(const uint8_t *uaddr);

static bool put_user(uint8_t *udst, uint8_t byte);

static int32_t validate_byte(const void *vaddr);

static size_t validate_buffer(const char *buffer);

static void read_mem_user(const void *src, void *dst, size_t bytes);

static void syscall_handler(struct intr_frame *);

/* Array of sys call handlers mapped to their specific code.
 * Each function is responsible for retrieving its own parameters
 * from the stack and setting the return result into the eax register.*/
intr_handler_func *handlers[HANDLED_SYSCALLS];

/* Lock to synchronize the file system - called whenever files are used. */
struct lock file_lock;

/*
 * Function: syscall_init()
 * ---------------------------
 * Initialise the syscall system by setting up the handlers array
 * and the file descriptor global counter.
 */
void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  // Map each handler function to its position in the array.
  handlers[SYS_HALT] = &sys_halt;
  handlers[SYS_EXIT] = &sys_exit;
  handlers[SYS_EXEC] = &sys_exec;
  handlers[SYS_WAIT] = &sys_wait;
  handlers[SYS_CREATE] = &sys_create;
  handlers[SYS_REMOVE] = &sys_remove;
  handlers[SYS_OPEN] = &sys_open;
  handlers[SYS_FILESIZE] = &sys_filesize;
  handlers[SYS_READ] = &sys_read;
  handlers[SYS_WRITE] = &sys_write;
  handlers[SYS_SEEK] = &sys_seek;
  handlers[SYS_TELL] = &sys_tell;
  handlers[SYS_CLOSE] = &sys_close;
  handlers[SYS_MMAP] = &sys_mmap;
  handlers[SYS_MUNMAP] = &sys_munmap;
  lock_init(&file_lock);
}

/*
 * Function: syscall_handler()
 * -----------------------------
 * Reads the syscall number from the stack and dispaches the
 * frame to the corresponding function. Exits if the
 * stack pointer or the handler code are invalid.
 * Param f - frame of the caller
 */
static void syscall_handler(struct intr_frame *f) {
  uint32_t handler_code;
  read_mem_user(f->esp, &handler_code, sizeof(handler_code));
  if (handler_code >= HANDLED_SYSCALLS) {
    sys_exit(SAFE_EXIT);
  }
  handlers[handler_code](f);
}

/* Function: sys_halt()
 * --------------------
 * Terminate the machine if possible */
void sys_halt(struct intr_frame *f UNUSED) { shutdown_power_off(); }

/* Function: sys_exit()
 * --------------------
 * Reads the exit code from the stack if not null and
 * exits the thread with said code. If the stack is null
 * the thread is exitting due to an error: -1.
 * Param status - exit code of the thread
 */
void sys_exit(struct intr_frame *f) {
  if (lock_held_by_current_thread(&file_lock)) {
    lock_release(&file_lock);
  }
#ifdef VM
  if (lock_held_by_current_thread(&frame_lock)) {
    lock_release(&frame_lock);
  }

  if (lock_held_by_current_thread(&swap_lock)) {
    lock_release(&swap_lock);
  }
#endif

  int32_t status;
  /* Try to read the exit code of the thread from the stack */
  if (f == SAFE_EXIT) {
    status = ERROR;
  } else {
    read_mem_user(f->esp + 4, &status, sizeof(status));
  }
  struct thread *curr = thread_current();
  printf("%s: exit(%d)\n", &curr->name[0], status);

  /* If the current thread is a child, pass its exit status to
     its child_elem. We have to disable interrupts here to
     ensure the curr->duty isn't null when we access it. There
     is no other way of doing this without significantly
     increasing synchronisation complexity. */
  lock_acquire(&duty_lock);
  if (curr->duty != NULL) {
    curr->duty->exit_status = status;
  }
  lock_release(&duty_lock);

  process_exit();
  thread_exit();
}

/* Function: sys_exec()
 * --------------------
 * Runs the executable whose name is given in cmd_line
 * Copies the process's exit code into f->eax
 * Param cmd_line - the command line being used to execute
 * Param code - the exit code of the execution
 *
 * Returns - Passes the exit code of execution into the frame's
 *           eax register
 */
void sys_exec(struct intr_frame *f) {
  char *cmd_line;
  read_mem_user(f->esp + 4, &cmd_line, sizeof(cmd_line));
  /* cmd_line is the address to the buffer so must check it's valid. */
  size_t l = validate_buffer(cmd_line);

#ifdef VM
  pin_frame(cmd_line, l);
#endif
  tid_t code = process_execute(cmd_line);
#ifdef VM
  unpin_frame(cmd_line, l);
#endif
  f->eax = (uint32_t)code;
}

/* Function: sys_wait()
 * --------------------
 * Waits for a child process pid and retrieves the exit status,
 * placing this in f->eax
 * Param pid - the Id of the thread to wait
 * Param code - exit code of the process wait
 *
 * Returns - Sets the exit code of process wait into the frame's
 *           eax register
 */
void sys_wait(struct intr_frame *f) {
  pid_t pid;
  read_mem_user(f->esp + 4, &pid, sizeof(pid_t));
  int code = process_wait(pid);
  f->eax = (uint32_t)code;
}

/* Function: sys_create()
 * ----------------------
 * Create a new file init_size bytes in size named file_name
 * Param file_name - name of the file to be created
 * Param init_size - initial size of the file
 * Param success - boolean of if creation was successful
 *
 * Returns - Sets eax to be true or false if successful
 */
void sys_create(struct intr_frame *f) {
  const char *file_name;
  unsigned init_size;
  bool success;

  read_mem_user(f->esp + 4, &file_name, sizeof(file_name));
  read_mem_user(f->esp + 8, &init_size, sizeof(init_size));
  size_t l = validate_buffer(file_name);

#ifdef VM
  pin_frame(file_name, l);
#endif
  lock_acquire(&file_lock);
  success = filesys_create(file_name, init_size);
  lock_release(&file_lock);
#ifdef VM
  unpin_frame(file_name, l);
#endif

  f->eax = (uint32_t)success;
}

/* Function: sys_remove()
 * ----------------------
 * Deletes the file of the given filename, if possible
 * Param file_name - name of the file to be removed
 * Param success - boolean of if removal was successful
 *
 * Returns - Sets eax to be true or false if successful
 */
void sys_remove(struct intr_frame *f) {
  const char *file_name;
  bool success;

  read_mem_user(f->esp + 4, &file_name, sizeof(file_name));
  size_t l = validate_buffer(file_name);

#ifdef VM
  pin_frame(file_name, l);
#endif

  lock_acquire(&file_lock);
  success = filesys_remove(file_name);
  lock_release(&file_lock);

#ifdef VM
  unpin_frame(file_name, l);
#endif

  f->eax = (uint32_t)success;
}

/* Function: sys_open()
 * --------------------
 * Opens the file of the given filename and copies the
 * file descriptor for the opened file into f->eax
 * Param file_name - name of file to be opened
 *
 * Returns - Sets the eax to be the fd of the file opened
 */
void sys_open(struct intr_frame *f) {
  const char *filename;
  read_mem_user(f->esp + 4, &filename, sizeof(filename));
  size_t l = validate_buffer(filename);
#ifdef VM
  pin_frame(filename, l);
#endif

  lock_acquire(&file_lock);
  struct file *file = filesys_open(filename);
  lock_release(&file_lock);

#ifdef VM
  unpin_frame(filename, l);
#endif
  /* If the file couldn't be opened return -1. */
  if (!file) {
    f->eax = (uint32_t)ERROR;
  } else {
    /* Allocate space for a new file descriptor (quit with -1
       if this can't be done), increment the fd count and push
       it to the list of opened file. */
    struct file_elem *fe = (struct file_elem *)malloc(sizeof(struct file_elem));
    if (fe == NULL) {
      f->eax = (uint32_t)ERROR;
      file_close(file);
      return;
    }
    fe->file = file;
    fe->fd = thread_current()->next_fd++;

    list_push_back(&thread_current()->open_files, &fe->elem);
    f->eax = (uint32_t)fe->fd;
  }
}

/* Function: sys_filesize()
 * ------------------------
 * Obtain the filesize of the given file, if possible.
 * Copy this into f->eax.
 * Param fd - file descriptor of file to be measured
 * Param size - size of the file
 *
 * Returns - Sets the eax to be the size of the file
 */
void sys_filesize(struct intr_frame *f) {
  int fd;
  int size = 0;
  read_mem_user(f->esp + 4, &fd, sizeof(fd));

  struct file_elem *result = get_file_elem_from_fd(fd, thread_current());
  if (result) {
    lock_acquire(&file_lock);
    size = file_length(result->file);
    lock_release(&file_lock);
  }

  f->eax = (uint32_t)size;
}

/* Function: sys_read()
 * --------------------
 * Read size bytes from file or from stdin into the buffer.
 * Copy into f->eax the actual number of bytes read from
 * the file.
 * Param fd - file descriptor of file to be read
 * Param code - number of bytes read
 * Param buffer - buffer for read bytes to be stored in
 * Param size - number of bytes to be read
 *
 * Returns - Sets the eax to be the number of bytes read
 */
void sys_read(struct intr_frame *f) {
  int fd;
  int code = 0;
  void *buffer;
  unsigned size;

  read_mem_user(f->esp + 4, &fd, sizeof(fd));
  read_mem_user(f->esp + 8, &buffer, sizeof(buffer));
  read_mem_user(f->esp + 12, &size, sizeof(size));

  validate_byte(buffer);
  validate_byte(buffer + size - 1);

  /* Read from stdin. */
  if (fd == STDIN_FILENO) {
#ifdef VM
    pin_frame(buffer, size);
#endif
    for (unsigned i = 0; i < size; ++i) {
      if (!put_user(buffer + i, input_getc())) {
        sys_exit(SAFE_EXIT);
      }
    }
#ifdef VM
    unpin_frame(buffer, size);
#endif
    code = size;
  } else if (fd == STDOUT_FILENO) {
    code = ERROR;
  } else {
    /* Read from the file. */
    struct file_elem *result = get_file_elem_from_fd(fd, thread_current());
    if (result) {
#ifdef VM
      pin_frame(buffer, size);
#endif
      lock_acquire(&file_lock);
      code = file_read(result->file, buffer, size);
      lock_release(&file_lock);
#ifdef VM
      unpin_frame(buffer, size);
#endif
    }
  }
  f->eax = (uint32_t)code;
}

/* Function: sys_write()
 * ---------------------
 * Write size bytes from the buffer into the open file.
 * Copies into f->eax the number of bytes actually
 * written to the file.
 * Param fd - file descriptor of file to be written to
 * Param buffer - data to be written to file
 * Param length - length of data to be written
 *
 * Returns - Sets eax to be number of bytes written
 */
void sys_write(struct intr_frame *f) {
  int fd;
  const void *buffer;
  unsigned length;

  read_mem_user(f->esp + 4, &fd, sizeof(fd));
  read_mem_user(f->esp + 8, &buffer, sizeof(buffer));
  read_mem_user(f->esp + 12, &length, sizeof(length));

  validate_byte(buffer);
  validate_byte(buffer + length - 1);

  if (fd == STDIN_FILENO) {
    f->eax = (uint32_t)ERROR;
  } else if (fd == STDOUT_FILENO) {
    size_t size = length;
/* If the size of the buffer is greater than some
   maximum size, we have to break up the write
   into smaller segments. */
#ifdef VM
    pin_frame(buffer, length);
#endif
    while (size > MAX_BUFFER_LENGTH) {
      putbuf(buffer, MAX_BUFFER_LENGTH);
      size -= MAX_BUFFER_LENGTH;
      buffer += MAX_BUFFER_LENGTH;
    }

    /* When size < maximum size, we can do it in
       one write. */
    putbuf(buffer, size);
#ifdef VM
    unpin_frame(buffer, length);
#endif
    f->eax = (uint32_t)size;
  } else {
    struct file_elem *result = get_file_elem_from_fd(fd, thread_current());

    if (result) {
#ifdef VM
      pin_frame(buffer, length);
#endif
      lock_acquire(&file_lock);
      f->eax = (uint32_t)file_write(result->file, buffer, length);
      lock_release(&file_lock);
#ifdef VM
      unpin_frame(buffer, length);
#endif
    }
  }
}

/* Function: sys_seek()
 * --------------------
 * Change the next byte to be read or written to
 * for the given file to pos
 * Param fd - file descriptor of file to be written to
 * Param pos - position of byte to be read/written
 */
void sys_seek(struct intr_frame *f) {
  int fd;
  unsigned pos;

  read_mem_user(f->esp + 4, &fd, sizeof(fd));
  read_mem_user(f->esp + 8, &pos, sizeof(pos));

  struct file_elem *result = get_file_elem_from_fd(fd, thread_current());
  if (result) {
    lock_acquire(&file_lock);
    file_seek(result->file, pos);
    lock_release(&file_lock);
  }
}

/* Function: sys_tell()
 * --------------------
 * Copies into f->eax the next byte to be read or
 * written in the file
 * Param fd - file descriptor of file to be written to
 * Param next_pos - position of the byte to be next read or written to
 *
 * Returns - Sets the eax to be the next byte's pos
 */
void sys_tell(struct intr_frame *f) {
  int fd;
  int next_pos = -1;

  read_mem_user(f->esp + 4, &fd, sizeof(fd));

  struct file_elem *result = get_file_elem_from_fd(fd, thread_current());
  if (result) {
    lock_acquire(&file_lock);
    next_pos = file_tell(result->file);
    lock_release(&file_lock);
  }

  f->eax = (uint32_t)next_pos;
}

/* Function: sys_close()
 * ---------------------
 * Closes the file fd and removes its associated
 * mapping, if possible.
 * Param fd - file descriptor of file to be written to
 */
void sys_close(struct intr_frame *f) {
  int fd;
  read_mem_user(f->esp + 4, &fd, sizeof(fd));

  struct file_elem *fe = get_file_elem_from_fd(fd, thread_current());
  /* If the retrieval of the file descriptor was successful then
     close the file and free. */
  if (fe) {
    file_close(fe->file);
    list_remove(&fe->elem);
    free(fe);
  }
}

#ifdef VM
/* Function: sys_mmap()
 * ---------------------
 * Lazily maps a given file at user virtual address. The allocation
 * fails with -1 if the fd does not exist, the length of the file
 * is 0, the address is 0, the address is not memory alligned,
 * there is not enough memory at the address or the address expands
 * over the stack space.
 * Param fd   - file descriptor of the open file to map
 * Param addr - address to map to
 * Returns    - id of the mapping
 */
void sys_mmap(struct intr_frame *f) {
  int fd;
  void *addr;
  read_mem_user(f->esp + 4, &fd, sizeof(fd));
  read_mem_user(f->esp + 8, &addr, sizeof(addr));

  /* Get the file struct for the given fd if it exits. */
  struct thread *t = thread_current();
  struct file_elem *e = get_file_elem_from_fd(fd, t);
  lock_acquire(&file_lock);
  struct file *file = e ? file_reopen(e->file) : NULL;
  off_t size;

  /* Check if the provided fd and address are valid, if not exit. */
  if (e == NULL || !(size = file_length(file)) || addr == 0 ||
      (uint32_t)addr % PGSIZE != 0 || addr >= STACK_GROWTH_LIMIT) {
    lock_release(&file_lock);
    f->eax = (uint32_t) MAP_FAILED;
    return;
  } else {
    lock_acquire(&t->spt_lock);
    /* Check that none of the pages of this file are in the SPT or in the
     * page table. */
    for (void *pg = addr; (int)pg < (int)addr + size; pg = pg + PGSIZE) {
      if (spt_lookup(&t->spt, pg) != NULL) {
        lock_release(&t->spt_lock);
        lock_release(&file_lock);
        f->eax = (uint32_t) MAP_FAILED;
        return;
      }
    }

    /* Allocate a new element in the SPT for lazy loading and insert. */
    for (void *pg = addr; (int)pg < (int)addr + size; pg = pg + PGSIZE) {
      uint32_t read_bytes =
          addr + size > pg + PGSIZE ? PGSIZE : addr + size - pg;
      uint32_t zero_bytes = PGSIZE - read_bytes;
      struct spt_elem *lazy_elem = new_file_page(
          pg, file, pg - addr, read_bytes, zero_bytes, true, false);
      hash_insert(&t->spt, &lazy_elem->elem);
    }

    lock_release(&t->spt_lock);
    lock_release(&file_lock);

    struct mmap_file *m_f = new_mmap_file(addr, file, size);
    hash_insert(&t->mmap_files, &m_f->elem);
    f->eax = (uint32_t)m_f->id;
  }
}

/* Function: sys_munmap()
 * ---------------------
 * Unmaps a given memory_mapping, writing back to disk
 * if needed.
 * Param mapping - id of the mapping
 */
void sys_munmap(struct intr_frame *f) {
  int mapping;
  read_mem_user(f->esp + 4, &mapping, sizeof(mapping));

  struct mmap_file *m_f = lookup_mmap_file(mapping);
  if (m_f != NULL) {
    struct thread *t = thread_current();
    lock_acquire(&file_lock);
    lock_acquire(&t->spt_lock);
    hash_delete(&t->mmap_files, &m_f->elem);
    mmap_file_destroy(&m_f->elem, NULL);
    lock_release(&t->spt_lock);
    lock_release(&file_lock);
  }
}

#endif

/* Function: get_file_elem_from_fd()
 * ---------------------------------
 * Iterate through a thread's files and find the one with
 * the matching file descriptor fd.
 * Param fd - file descriptor of file to be fetched
 * Param t - thread that holds the file
 *
 * Returns - The file_elem mapping associated with the given
 *           file descriptor in t's open_files list, NULL otherwise
 */
struct file_elem *get_file_elem_from_fd(int fd, struct thread *t) {
  struct list_elem *e;

  for (e = list_begin(&t->open_files); e != list_end(&t->open_files);
       e = list_next(e)) {
    struct file_elem *felem = list_entry(e, struct file_elem, elem);
    if (felem->fd == fd) {
      return felem;
    }
  }

  return NULL;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int get_user(const uint8_t *uaddr) {
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user(uint8_t *udst, uint8_t byte) {
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}

/* Function: validate_byte()
 * ---------------------------------
 * Validate the given pointer and abort if
 * it doesn't point to user space or a segfault occurs.
 * Param vaddr - Address to be validated
 */
static int32_t validate_byte(const void *vaddr) {
  if (is_user_vaddr(vaddr)) {
    int32_t value = get_user(vaddr);
    if (value != ERROR) {
      return value;
    }
  }
  sys_exit(SAFE_EXIT);
  return -1;
}

/* Function: validate_buffer()
 * ---------------------------------
 * Validate each byte of the given buffer untill the NULL
 * character is encountered.
 * Param buffer - Beginning of the buffer
 */
static size_t validate_buffer(const char *buffer) {
  size_t i = 0;
  do {
    validate_byte(buffer + i);
    i++;
  } while (buffer[i]);

  return i;
}

/* Function: read_mem_user()
 * ---------------------------------
 * Read a number of bytes from source and copies them
 * to destination, validating each byte.
 * Param src   - Address to read from
 * Param dst   - Address to copy to
 * Param bytes - Number of bytes to be read
 */
static void read_mem_user(const void *src, void *dst, size_t bytes) {
  int32_t value;

  for (size_t i = 0; i < bytes; i++) {
    value = validate_byte(src + i);
    *(char *)(dst + i) = value & 0xff;
  }
}
