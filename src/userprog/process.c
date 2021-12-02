#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#include "vm/frame.h"
#include "vm/mmap.h"
#include "vm/page.h"

#define PAGE_SIZE_KB (PGSIZE / 1024)
#define stack_round(INTR_FRAME) \
  (INTR_FRAME.esp -= (uintptr_t)INTR_FRAME.esp % PAGE_SIZE_KB)
#define stack_decrement_page(INTR_FRAME) \
  (INTR_FRAME.esp -= (uintptr_t)PAGE_SIZE_KB)
#define stack_decrement(INTR_FRAME, LENGTH) \
  (INTR_FRAME.esp -= (uintptr_t)LENGTH)

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);

/*
 * Function: check_thread_magic()
 * ------------------------------
 * Check if the magic member of the current thread is still
 * equal to THREAD_MAGIC and if not, stop right away because
 * a stack overflow has occured.
 * Param argv    - Pointer to arguments to deallocate.
 * Param success - Pointer to success boolean to report to process_execute.
 * Param sema    - Pointer to the semaphore blocking the parent.
 */
static void check_thread_magic(char **argv, bool *success,
                               struct semaphore *sema) {
  struct thread *curr = thread_current();
  if (curr->magic != THREAD_MAGIC) {
    palloc_free_page(argv);
    *success = false;
    sema_up(sema);
    sys_exit(SAFE_EXIT);
  }
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name) {
  char *fn_copy, *fn_copy2;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) return TID_ERROR;

  fn_copy2 = palloc_get_page(0);
  if (fn_copy2 == NULL) {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }

  char *aux_fn_copy2 = fn_copy2;
  strlcpy(fn_copy, file_name, PGSIZE);
  strlcpy(fn_copy2, file_name, PGSIZE);
  char *process_name;
  process_name = strtok_r(fn_copy2, " ", &fn_copy2);

  /* Pass the semaphore and the boolean as arguments
     to wait for full init of the process. */
  struct semaphore init_waiter;
  bool success = true;
  sema_init(&init_waiter, 0);
  void *args[3] = {fn_copy, &init_waiter, &success};

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(process_name, PRI_DEFAULT, start_process, args);

  /* Free the auxiliary char* used for storing the name and if the
    process failed starting and/or loading, deallocate the page
    used for its name and return. */
  palloc_free_page(aux_fn_copy2);
  if (tid != TID_ERROR) {
    sema_down(&init_waiter);
    tid = success ? tid : TID_ERROR;
  }

  if (tid == TID_ERROR) {
    palloc_free_page(fn_copy);
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void *args) {
  void **arg_list = (void **)args;
  char *file_name = arg_list[0];
  struct semaphore *init_wait = arg_list[1];
  bool *success = arg_list[2];

  struct intr_frame if_;

#ifdef VM
  /* Initialise the Supplemental Page Table */
  struct thread *t = thread_current();
  hash_init(&t->spt, hash_spt_elem, spt_compare, NULL);
  lock_init(&t->spt_lock);
  t->next_mmap_id = MAP_START;
  hash_init(&t->mmap_files, &hash_mmap_file, &mmap_file_compare, NULL);
#endif

  char **argv = (char **)palloc_get_page(0);
  /* If the allocation failed then set success to false,
    wake up the parent and exit safely. */
  if (argv == NULL) {
    *success = false;
    sema_up(init_wait);
    sys_exit(SAFE_EXIT);
  }
  /* Count the number of tokens in the filename and insert each token into an
   * array */
  char *token, *save_ptr;
  int argc = 0;
  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL;
       token = strtok_r(NULL, " ", &save_ptr)) {
    argv[argc++] = token;
  }

  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  lock_acquire(&file_lock);
  *success = load(file_name, &if_.eip, &if_.esp);
  lock_release(&file_lock);
  /* If load failed, quit. */
  if (!*success) {
    sema_up(init_wait);
    palloc_free_page(argv);
    sys_exit(SAFE_EXIT);
  }
  void *addresses[argc];
  /* Push each argument onto the stack and store its address in argv */
  for (int i = 0; i < argc; i++) {
    int length = strlen(argv[i]) + 1;  // Include null terminator
    stack_decrement(if_, length);
    memcpy((char *)if_.esp, argv[i], length);
    addresses[i] = (char *)if_.esp;
    check_thread_magic(argv, success, init_wait);
  }

  /* Round the stack pointer down to the nearest multiple of 4 */
  stack_round(if_);

  stack_decrement_page(if_);
  *((char *)if_.esp) = 0;
  check_thread_magic(argv, success, init_wait);

  /* Push the pointers to each argument onto the stack */
  for (int i = argc - 1; i >= 0; i--) {
    stack_decrement_page(if_);
    *((void **)if_.esp) = addresses[i];
    check_thread_magic(argv, success, init_wait);
  }

  /* Push the address of argv onto the stack */
  stack_decrement_page(if_);
  *((char **)if_.esp) = (if_.esp + 4);
  check_thread_magic(argv, success, init_wait);

  /* Push argc onto the stack */
  stack_decrement_page(if_);
  *((int *)if_.esp) = argc;
  check_thread_magic(argv, success, init_wait);

  /* Push a fake return address onto the stack */
  stack_decrement_page(if_);
  *((int *)if_.esp) = 0;
  check_thread_magic(argv, success, init_wait);
  sema_up(init_wait);

  palloc_free_page(argv);
  palloc_free_page(file_name);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/*
 * Function: process_wait()
 * ------------------------
 * Waits for thread child_tid to die and returns its
 * exit status even if the process has already terminated.
 * Param child_tid - Id of the child to wait for
 *
 * Returns - Exit code of child_tid or -1 if this isn't a
 *           child of the current process.
 */
int process_wait(tid_t child_tid) {
  struct thread *t = thread_current();

  struct child_elem *ce = NULL;
  struct list_elem *e;

  lock_acquire(&duty_lock);
  /* Check whether child_tid belongs to a child of the
     currently running thread. */
  for (e = list_begin(&t->children); e != list_end(&t->children);
       e = list_next(e)) {
    struct child_elem *child = list_entry(e, struct child_elem, elem);
    if (child->thread_tid == child_tid) {
      ce = child;
      break;
    }
  }

  /* Return -1 if child_tid is invalid or was not a child. */
  if (ce == NULL) {
    lock_release(&duty_lock);
    return -1;
  }

  /* Check if the exit_status has already been set. */
  if (ce->exit_status == INVALID_STATUS) {
    /* Create a semaphore to block the current thread
       and set it in ce so the child wakes the parent up. */
    struct semaphore wait;
    sema_init(&wait, 0);
    ce->wait = &wait;
    lock_release(&duty_lock);
    sema_down(&wait);
  } else {
    lock_release(&duty_lock);
  }

  int return_status = ce->exit_status;
  list_remove(&ce->elem);
  free(ce);
  return return_status;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread *curr = thread_current();

  bool acquired_frame = lock_try_acquire_and_block(&frame_lock);
  bool acquired_spt = lock_try_acquire_and_block(&curr->spt_lock);
#ifdef VM
  hash_destroy(&curr->mmap_files, &mmap_file_destroy);
  hash_destroy(&curr->spt, &spt_elem_destroy);
#endif

  uint32_t *pd;
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = curr->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    curr->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  lock_conditional_release(&curr->spt_lock, acquired_spt);
  lock_conditional_release(&frame_lock, acquired_frame);

  /* Iterate through each of the files opened by this
     terminating process and close them, freeing memory. */
  while (!list_empty(&curr->open_files)) {
    struct list_elem *e = list_pop_front(&curr->open_files);
    struct file_elem *fe = list_entry(e, struct file_elem, elem);
    file_close(fe->file);
    free(fe);
  }

  // Close the process executable
  file_close(curr->open_exec);

  lock_acquire(&duty_lock);
  /* Iterate through each child of the current thread,
     remove them from the parent thread, set their
     child_elem to NULL and free them. */
  while (!list_empty(&curr->children)) {
    struct list_elem *e = list_pop_front(&curr->children);
    struct child_elem *child = list_entry(e, struct child_elem, elem);
    if (child->t != NULL) {
      child->t->duty = NULL;
    }
    free(child);
  }

  /* If the parent of this process is waiting for it
     to terminate then unblock it. */
  curr->duty->t = NULL;
  if (curr->duty != NULL && curr->duty->wait != NULL) {
    sema_up(curr->duty->wait);
  }
  lock_release(&duty_lock);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void) {
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp) {
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL) {
    file_close(file);
    goto done;
  }
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    file_close(file);
    goto done;
  }
  file_deny_write(file);
  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 3 || ehdr.e_version != 1 ||
      ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    file_close(file);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file)) {
      file_close(file);
      goto done;
    }
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) {
      file_close(file);
      goto done;
    }
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
               Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes =
                (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
               Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void *)mem_page, read_bytes,
                            zero_bytes, writable)) {
            file_close(file);
            goto done;
          }
        } else {
          file_close(file);
          goto done;
          break;
        }
    }
  }
  /* Set up stack. */
  if (!setup_stack(esp)) {
    file_close(file);
    goto done;
  }

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;
  t->open_exec = file;
  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr *phdr, struct file *file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file)) return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0) return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr)) return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz))) return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE) return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Check if virtual page already allocated */
    struct thread *t = thread_current();
    lock_acquire(&t->spt_lock);
    struct spt_elem *stored_lazy_elem = spt_lookup(&t->spt, upage);

    if (stored_lazy_elem == NULL) {
      struct spt_elem *lazy_elem = new_file_page(
          upage, file, ofs, page_read_bytes, page_zero_bytes, writable, true);
      hash_insert(&t->spt, &lazy_elem->elem);
    } else {
      stored_lazy_elem->file_data->read_bytes = page_read_bytes;
      stored_lazy_elem->file_data->zero_bytes = page_zero_bytes;
      stored_lazy_elem->file_data->offset = ofs;
      stored_lazy_elem->writable = stored_lazy_elem->writable || writable;
      stored_lazy_elem->executable = true;
    }
    lock_release(&t->spt_lock);

    /* Advance. */
    ofs += page_read_bytes;
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void **esp) {
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    lock_acquire(&frame_lock);
    lock_acquire(&thread_current()->spt_lock);
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true, false,
                           NULL, 0);
    if (success) {
      *esp = PHYS_BASE;
      struct spt_elem *e = new_present_page(((uint8_t *)PHYS_BASE) - PGSIZE);
      hash_insert(&thread_current()->spt, &e->elem);
    } else {
      palloc_free_page(kpage);
    }
    lock_release(&thread_current()->spt_lock);
    lock_release(&frame_lock);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool install_page(void *upage, void *kpage, bool writable, bool is_file,
                  struct file *file, off_t ofs) {
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool result = pagedir_get_page(t->pagedir, upage) == NULL &&
                pagedir_set_page(t->pagedir, upage, kpage, writable);
#ifdef VM
  struct frame_elem *f = frame_lookup(vtop(kpage));
  if (result && !f) {
    f = frame_create();
    ASSERT(f);

    f->frame_address = vtop(kpage);
    f->writable = writable;

    f->is_file = is_file;
    f->file = file;
    f->ofs = ofs;

    hash_insert(&frame_table, &f->elem);
  }

  if (result) {
    struct page_mapping *pm = mapping_create(t, upage);
    list_push_back(&f->page_mappings, &pm->elem);
  }
#endif
  return result;
}
