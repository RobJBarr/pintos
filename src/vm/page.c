#include "vm/page.h"

#include <string.h>

#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/swap.h"

static bool load_swap(struct spt_elem *e);

/* Function: hash_spt_elem()
 * -------------------------
 * Creates a hash for a given SPT elem's hash elem using the
 * user virtual address
 * Param e - SPT elem
 *
 * Returns - hashed value of the user virtual address
 */
unsigned hash_spt_elem(const struct hash_elem *e, void *aux UNUSED) {
  unsigned address = (unsigned)hash_entry(e, struct spt_elem, elem)->uvaddr;
  return hash_int(address);
}

/* Function: spt_compare()
 * -----------------------
 * Compares two SPT elems for insertion
 * Param a - first spt elem
 * Param b - second spt elem
 *
 * Returns - true if a < b
 */
bool spt_compare(const struct hash_elem *a, const struct hash_elem *b,
                 void *aux UNUSED) {
  struct spt_elem *spt1 = hash_entry(a, struct spt_elem, elem);
  struct spt_elem *spt2 = hash_entry(b, struct spt_elem, elem);
  return spt1->uvaddr < spt2->uvaddr;
}

/* Function: spt_elem_destroy()
 * ----------------------------
 * Destroys an SPT elem by freeing its data and the elem itself
 * Param e - elem to be freed
 */
void spt_elem_destroy(struct hash_elem *e, void *aux UNUSED) {
  struct spt_elem *spt_e = hash_entry(e, struct spt_elem, elem);
  if (spt_e->type == SWAP) {
    lock_acquire(&swap_lock);
    swap_get_and_remove(spt_e->swap_index, 0);
    lock_release(&swap_lock);
  }

  free(spt_e->file_data);
  free(spt_e);
}

/* Function: spt_lookup()
 * ----------------------
 * Gets an SPT elem from a given user virtual address in the
 * given SPT
 * Param spt    - SPT to look for elem
 * Param uvaddr - the address of the elem being searched
 *
 * Returns      - SPT elem if it is found or NULL
 */
struct spt_elem *spt_lookup(struct hash *spt, void *uvaddr) {
  struct spt_elem spt_e;
  spt_e.uvaddr = uvaddr;

  struct hash_elem *elem = hash_find(spt, &spt_e.elem);
  if (!elem) {
    return NULL;
  }
  return hash_entry(elem, struct spt_elem, elem);
}

/* Function: stack_grow()
 * ----------------------
 * Grow the stack by one page when there is a stack overflow
 * Param uvaddr - the user virtual address of the page fault
 * 
 * Returns      - bool signalling whether it was successful or not
 */
bool stack_grow(void *uvaddr) {
  struct thread *curr = thread_current();
  bool acq_frame = lock_try_acquire_and_block(&frame_lock);
  bool acq_spt = lock_try_acquire_and_block(&curr->spt_lock);

  struct spt_elem *spte = new_present_page(uvaddr);
  void *kpage = palloc_get_page(PAL_USER);

  if (install_page(spte->uvaddr, kpage, true, false, NULL, 0) == false) {
    free(spte);
    lock_conditional_release(&curr->spt_lock, acq_spt);
    lock_release(&frame_lock);
    return false;
  }

  /* Insert the new page into the SPT. */
  hash_insert(&curr->spt, &spte->elem);
  lock_conditional_release(&curr->spt_lock, acq_spt);
  lock_conditional_release(&frame_lock, acq_frame);
  return true;
}

/* Function: new_file_page()
 * -------------------------
 * Create a new page of type FILE_SYS and assign it the given values
 * Param uvaddr     - user virtual address of page
 * Param file       - the file that the page is holding
 * Param offset     - the offset into the file
 * Param read_bytes - number of bytes to read
 * Param zero_bytes - number of bytes to zero
 * Param writable   - if it is writable or not
 *
 * Returns          - newly created SPT elem
 */
struct spt_elem *new_file_page(void *uvaddr, struct file *file, off_t offset,
                               uint32_t read_bytes, uint32_t zero_bytes,
                               bool writable, bool executable) {
  struct spt_elem *e = (struct spt_elem *)malloc(sizeof(struct spt_elem));
  if (!e) {
    PANIC("KERNEL RAN OUT OF MEMORY");
  }

  e->uvaddr = uvaddr;
  e->type = FILE_SYS;
  e->writable = writable;
  e->executable = executable;

  struct filesys_data *data =
      (struct filesys_data *)malloc(sizeof(struct filesys_data));
  if (!data) {
    PANIC("KERNEL RAN OUT OF MEMORY");
  }
  data->file = file;
  data->offset = offset;
  data->read_bytes = read_bytes;
  data->zero_bytes = zero_bytes;

  e->file_data = data;
  return e;
}

/* Function: new_present_page()
 * -------------------------
 * Create a new page of type PRESENT and assign it the given values.
 * Param uvaddr - user virtual address of page
 * Param kpage  - kernel virtual address of page
 *
 * Returns      - newly created SPT elem, can panic the kernel
 */
struct spt_elem *new_present_page(void *uvaddr) {
  struct spt_elem *e = (struct spt_elem *)malloc(sizeof(struct spt_elem));
  if (!e) {
    PANIC("KERNEL RAN OUT OF MEMORY");
  }

  e->uvaddr = uvaddr;
  e->type = PRESENT;
  e->writable = true;
  e->file_data = NULL;
  return e;
}

/* Function: set_swap()
 * -------------------------
 * Set a page to be swapped.
 * Param t          - the thread whose SPT we will use
 * Param uvaddr     - user virtual address of page
 * Param swap_index - the index for the swap table
 *
 * Return           - true if it has been successfully swapped.
 */
bool set_swap(struct thread *t, void *uvaddr, block_sector_t swap_index) {
  struct spt_elem *e = spt_lookup(&t->spt, uvaddr);
  if (e == NULL) return false;

  e->type = SWAP;
  e->swap_index = swap_index;
  return true;
}

/* Function: load_file_sys()
 * -------------------------
 * Given an spt_elem that stores a page part of a file
 * load the page into memory.
 * Params e - SPT elem to load
 *
 * Return   - true if successful
 */
bool load_file_sys(struct spt_elem *e) {
  void *kpage = palloc_get_page(PAL_USER);
  uint32_t page_read_bytes =
      e->file_data->read_bytes < PGSIZE ? e->file_data->read_bytes : PGSIZE;

  /* Add the page to the page table & to the frame table (in install_page)
   * and read into it from the file. */
  ASSERT(install_page(e->uvaddr, kpage, e->writable, true, e->file_data->file,
                      e->file_data->offset));

  off_t bytes_read = 0;
  if (page_read_bytes > 0) {
    lock_acquire(&file_lock);
    bytes_read = file_read_at(e->file_data->file, kpage, page_read_bytes,
                              e->file_data->offset);
    lock_release(&file_lock);
  }

  /* If the call read less than it should have, remove from the page dir,
   * free and return false. */
  if ((uint32_t)bytes_read != page_read_bytes) {
    pagedir_clear_page(thread_current()->pagedir, e->uvaddr);
    palloc_free_page(kpage);
    return false;
  }

  /* Add all 0s at the end. */
  memset(kpage + page_read_bytes, 0, PGSIZE - e->file_data->read_bytes);

  /* Make present */
  e->type = PRESENT;
  return true;
}

/* Function: load_swap()
 * ---------------------
 * Loads a page from swap using the given
 * spt_elem.
 * Param e - the spt to load the address from swap into
 *
 * Returns - true iff the load is successful
 */
static bool load_swap(struct spt_elem *e) {
  void *kpage = palloc_get_page(PAL_USER);
  lock_acquire(&swap_lock);
  swap_get_and_remove(e->swap_index, kpage);
  lock_release(&swap_lock);

  bool success;
  if (e->type == FILE_SYS) {
    ASSERT(e->file_data);
    success = install_page(e->uvaddr, kpage, e->writable, true,
                           e->file_data->file, e->file_data->offset);
    pagedir_set_dirty(thread_current()->pagedir, e->uvaddr, true);
  } else {
    success = install_page(e->uvaddr, kpage, e->writable, false, NULL, 0);
  }

  if (!success) {
    palloc_free_page(kpage);
  } else {
    e->type = PRESENT;
  }

  return success;
}

/* Function: page_load()
 * -------------------------
 * Load a page into a frame.
 * Param e - spt_elem to the uvaddr we want to load
 * Return  - true if the load was successful
 */
bool page_load(struct spt_elem *e) {
  /* We see if the page has already been loaded. */
  if (e->type == FILE_SYS &&
      ((!e->executable) || (e->executable && !e->writable))) {
    struct frame_elem *fe = frame_lookup_file(
        e->file_data->file, e->file_data->offset, e->writable);
    if (fe) {
      /* Page has already been loaded so we share. */
      install_page(e->uvaddr, ptov(fe->frame_address), e->writable, true,
                   e->file_data->file, e->file_data->offset);

      e->type = PRESENT;
      return true;
    }
  }

  switch (e->type) {
    case FILE_SYS:
      return load_file_sys(e);
    case SWAP:
      return load_swap(e);
    case PRESENT:
      ASSERT(false);
  }

  return false;
}
