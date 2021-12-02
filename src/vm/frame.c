#include "vm/frame.h"

#include <debug.h>

#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/mmap.h"
#include "vm/page.h"
#include "vm/swap.h"

#define offset_pages(OFFSET) ((int)(OFFSET / PGSIZE))

struct lock frame_lock;
struct hash frame_table;

struct frame_elem *frame_to_evict_helper(bool pinned);

/* Function: hash_frame()
 * ---------------------
 * A hash_hash_func that returns the hash value for a given hash_elem.
 * The params and return type follow those of a hash_hash_func:
 * Param e - the hash_elem we want to get the hash value of.
 *
 * Return  - unsigned value representing the hash of the elem.
 */
static unsigned hash_frame(const struct hash_elem *e, void *aux UNUSED) {
  return hash_int(hash_entry(e, struct frame_elem, elem)->frame_address);
}

/* Function: frame_compare()
 * ------------------------
 * A hash_less_func that compares two hash_elems. Returns true iff the value
 * for a is less than b.
 * The params and return values follow those of a hash_less_func:
 * Param a   - the first hash elem to compare
 * Param b   - the second hash elem to compare
 * Param aux - any other arguments required.
 *
 * Return    - true iff the value for a is less than that of b.
 */
static bool frame_compare(const struct hash_elem *a, const struct hash_elem *b,
                          void *aux UNUSED) {
  struct frame_elem *f1 = hash_entry(a, struct frame_elem, elem);
  struct frame_elem *f2 = hash_entry(b, struct frame_elem, elem);
  return f1->frame_address < f2->frame_address;
}

/* Function: remove_from_owners()
 * ------------------------------
 * Removes the current thread from the list of owners (if
 * it is the case) of a given frame_elem.
 * Param f - frame_elem to remove from
 *
 * Return  - true iff the list of owner is empty after
 *           the search and (possibly) the removal
 */
bool remove_from_owners(struct frame_elem *f) {
  struct thread *t = thread_current();

  struct list_elem *le;
  for (le = list_begin(&f->page_mappings); le != list_end(&f->page_mappings);
       le = list_next(le)) {
    struct page_mapping *pm = list_entry(le, struct page_mapping, elem);
    struct lock *l = &pm->owner->spt_lock;
    bool acquired = lock_try_acquire_and_block(l);

    /* If the mapping corresonds to the current thread, remove. */
    if (pm->owner == t) {
      list_remove(le);
      free(pm);
      lock_conditional_release(l, acquired);
      break;
    }

    lock_conditional_release(l, acquired);
  }

  if (list_empty(&f->page_mappings)) {
    return true;
  }

  return false;
}

/* Function: frame_destroy()
 * ------------------------
 * A hash_action_func used to deallocate the resources associated with
 * the frame table and all of its frame_elems.
 * Param e - the hash_elem to free the resources of.
 */
void frame_destroy(struct hash_elem *e, void *aux UNUSED) {
  struct frame_elem *f = hash_entry(e, struct frame_elem, elem);

  /* Free the page_mappings of the elem. */
  while (!list_empty(&f->page_mappings)) {
    struct list_elem *e_list = list_pop_front(&f->page_mappings);
    struct page_mapping *pm = list_entry(e_list, struct page_mapping, elem);
    free(pm);
  }

  free(f);
}

/* Function: frame_table_init()
 * ---------------------------
 * Initialises the frame table and its corresponding lock.
 */
void frame_table_init(void) {
  lock_init(&frame_lock);
  hash_init(&frame_table, &hash_frame, &frame_compare, NULL);
}

/* Function: frame_lookup()
 * ------------------------
 * a wrapper for hash_find for entries in the frame table.
 * Creates a dummy elem with the given frame address and then
 * calls hash find using this elem to obtain the actual frame
 * elem, or NULL if it doesn't exist.
 * Param frame_address - the frame address to look up in the
 *                       frame table
 *
 * Return              - a frame_elem corresponding to the frame address if
 *                       it is found, otherwise NULL.
 */
struct frame_elem *frame_lookup(uintptr_t frame_address) {
  struct frame_elem dummy_elem;
  dummy_elem.frame_address = frame_address;
  struct hash_elem *e = hash_find(&frame_table, &dummy_elem.elem);
  return e ? hash_entry(e, struct frame_elem, elem) : NULL;
}

/* Function: not_owned()
 * ----------------------
 * Checks if a given frame_elem is not owned by the current
 * thread.
 * Param f - frame_elem to check
 *
 * Returns - true iff f has thread_current() as an owner.
 */
static bool not_owned(struct frame_elem *f) {
  struct list_elem *e;
  for (e = list_begin(&f->page_mappings); e != list_end(&f->page_mappings);
       e = list_next(e)) {
    struct page_mapping *pm = list_entry(e, struct page_mapping, elem);
    if (pm->owner == thread_current()) {
      return false;
    }
  }
  return true;
}

/* Function: frame_lookup()
 * ------------------------
 * Looks for an entry in the frame table using the given file and
 * offset into the file. Returns the corresponding frame_elem if
 * one is found, or NULL otherwise.
 * Param file - the file to look for in the frame table
 * Param ofs  - the offset (within the file) to search for
 *
 * Return     - corresponding frame_elem if one is found that uses
 *              the same file and the same page within the file (from the
 *              offset) or NULL otherwise.
 */
struct frame_elem *frame_lookup_file(struct file *file, off_t ofs,
                                     bool writable) {
  struct inode *f_inode = file_get_inode(file);
  struct frame_elem *fe = NULL;
  struct hash_iterator i;

  hash_first(&i, &frame_table);
  while (hash_next(&i)) {
    struct frame_elem *f = hash_entry(hash_cur(&i), struct frame_elem, elem);
    if (f->file != NULL && file_get_inode(f->file) == f_inode &&
        ofs == f->ofs && writable == f->writable && not_owned(f)) {
      fe = f;
      break;
    }
  }

  return fe;
}

/* Function: frame_table_destroy()
 * ------------------------------
 * Used to destroy the frame table when the system terminates. This
 * is done using hash_destroy() with frame_destroy() - see the
 * documentation for frame_destroy().
 */
void frame_table_destroy(void) {
  /* we need to acquire the lock since we can't modify the frame table
   * during the destruction */
  hash_destroy(&frame_table, &frame_destroy);
}

/* Function: frame_create()
 * -----------------------
 * A utility function which allocates and initialises a frame_elem. If we can't
 * allocate the memory then we panic the kernel as this means we're out of
 * kernel memory (a very bad thing!)
 *
 * Return - a pointer to an allocated frame_elem. This should never be NULL.
 */
struct frame_elem *frame_create(void) {
  struct frame_elem *fe =
      (struct frame_elem *)malloc(sizeof(struct frame_elem));

  if (!fe) {
    PANIC("Out of memory!");
  }

  list_init(&fe->page_mappings);
  return fe;
}

/* Function: mapping_create()
 * -------------------------
 * Creates and allocates a page_mapping struct and initialises it to have
 * the given values t, page_address. If the allocation fails we panic the
 * kernel as this means we are out of kernel memory (a very bad thing!).
 * Param t            - the thread pointer to initialise the owner of
 *                      the mapping to
 * Param page_address - the page address to initialise the page address
 *                      of the mapping to.
 *
 * Return             - a page_mapping with its values initialised
 *                      to the given parameters.
 *                      This will never be NULL if it returns.
 */
struct page_mapping *mapping_create(struct thread *t, void *page_address) {
  struct page_mapping *pm =
      (struct page_mapping *)malloc(sizeof(struct page_mapping));

  if (!pm) {
    PANIC("Out of memory!");
  }

  pm->page_address = page_address;
  pm->owner = t;

  return pm;
}

/* Function: frame_get_accessed()
 * --------------------------
 * Loops through the frame's page mappings and does a lazy OR of all the
 * accessed values to check if the frame has been accessed Param f - the frame
 * whose accessed bit is being calculated Return a bool of its collective
 * accessed bit
 */
bool frame_get_accessed(struct frame_elem *f) {
  struct list_elem *e;
  for (e = list_begin(&f->page_mappings); e != list_end(&f->page_mappings);
       e = list_next(e)) {
    struct page_mapping *pm = list_entry(e, struct page_mapping, elem);
    if (pagedir_is_accessed(pm->owner->pagedir, pm->page_address)) {
      return true;
    }
  }
  return false;
}

/* Function: frame_get_dirty()
 * --------------------------
 * Loops through the frame's page mappings and does a lazy OR of all the dirty
 * values to check if the frame has been wrtten to
 * Param f - the frame whose dirty bit is being calculated
 *
 * Return  - true iff any of the page mappings have been written to.
 */
bool frame_get_dirty(struct frame_elem *f) {
  struct list_elem *e;
  for (e = list_begin(&f->page_mappings); e != list_end(&f->page_mappings);
       e = list_next(e)) {
    struct page_mapping *pm = list_entry(e, struct page_mapping, elem);
    if (pagedir_is_dirty(pm->owner->pagedir, pm->page_address)) {
      return true;
    }
  }

  return false;
}

/* Function: frame_unset_accessed()
 * --------------------------
 * Loops through the frame's page mappings and sets the accessed bit to be false
 * Param f - the frame whose accessed bit is being set
 */
void frame_unset_accessed(struct frame_elem *f) {
  struct list_elem *e;
  for (e = list_begin(&f->page_mappings); e != list_end(&f->page_mappings);
       e = list_next(e)) {
    struct page_mapping *pm = list_entry(e, struct page_mapping, elem);
    pagedir_set_accessed(pm->owner->pagedir, pm->page_address, false);
  }
}

/* Function: frame_set_swap()
 * --------------------------
 * Given a frame_elem and swap index, go through all the page mappings
 * and set them to a swap state.
 * Param f        - the frame elem to set to a swap state (being evicted)
 * Param swap_idx - the index in swap the address was written to (to be
 *                  stored in the SPT)
 */
void frame_set_swap(struct frame_elem *f, block_sector_t swap_idx) {
  struct list_elem *e;

  for (e = list_begin(&f->page_mappings); e != list_end(&f->page_mappings);
       e = list_next(e)) {
    struct page_mapping *pm = list_entry(e, struct page_mapping, elem);

    bool acquired = lock_try_acquire_and_block(&pm->owner->spt_lock);

    set_swap(pm->owner, pm->page_address, swap_idx);
    pagedir_clear_page(pm->owner->pagedir, pm->page_address);

    lock_conditional_release(&pm->owner->spt_lock, acquired);
  }
}

/* Function: frame_set_filesys()
 * -----------------------------
 * Given a frame elem, go through all the page mappings and set them
 * to the FILE_SYS state, so they can be loaded from the filesystem
 * again.
 * Param f - the frame elem to set to a FILE_SYS state
 */
void frame_set_filesys(struct frame_elem *f) {
  struct list_elem *e;
  for (e = list_begin(&f->page_mappings); e != list_end(&f->page_mappings);
       e = list_next(e)) {
    struct page_mapping *pm = list_entry(e, struct page_mapping, elem);

    bool acquired = lock_try_acquire_and_block(&pm->owner->spt_lock);

    struct spt_elem *e = spt_lookup(&pm->owner->spt, pm->page_address);
    ASSERT(e);
    e->type = FILE_SYS;
    pagedir_clear_page(pm->owner->pagedir, pm->page_address);

    lock_conditional_release(&pm->owner->spt_lock, acquired);
  }
}

/* Function: frame_to_evict_helper()
 * ---------------------------------
 * Helper function to pick the frame to evict. This loops through the frames
 * following the LRU Approximation algorithm. If pinned is true then pinned
 * frames will be skipped, otherwise they will be treated like normal frames
 * Param pinned - if true then pinned frames are skipped
 *
 * Returns      - the frame elem of the frame to evict
 */ 
struct frame_elem *frame_to_evict_helper(bool pinned) {
  struct hash_iterator next;
  struct frame_elem *frame;
  // Implementing the LRU Approximation algorithm
  for (int i = 0; i < 2; i++) {  // Loop twice to make sure a frame is found
    hash_first(&next, &frame_table);
    while (hash_next(&next)) {
      frame = hash_entry(hash_cur(&next), struct frame_elem, elem);
      if (pinned && frame->pinned)
        continue;
      else if (frame_get_accessed(frame)) {
        frame_unset_accessed(frame);
        continue;
      }
      return frame;
    }
  }
  return NULL;
}

/* Function: frame_to_evict()
 * --------------------------
 * Pick a frame to evict from the frame table
 *
 * Returns - the frame elem of the frame to be evicted
 */
struct frame_elem *frame_to_evict(void) {
  size_t n = hash_size(&frame_table);
  if (n == 0) PANIC("Frame table is empty");

  struct frame_elem *frame = frame_to_evict_helper(true);

  // if frame is NULL, all frames are pinned
  // so we redo the eviction algorithm without caring
  // if something is pinned
  if (!frame) {
    frame = frame_to_evict_helper(false);
  }

  if (!frame) {
    PANIC("Eviction failed");
  }
  return frame;
}

/* Function: evict_frame()
 * -----------------------
 * Gets the frame to evict and uses frame_destroy to remove the frame
 */
void evict_frame(void) {
  struct frame_elem *evictee = frame_to_evict();
  /* Write any altered filesys pages to swap */
  /* Write every stack page to swap */
  if (!evictee->is_file || (evictee->is_file && frame_get_dirty(evictee))) {
    lock_acquire(&swap_lock);
    block_sector_t swap_idx = swap_insert(ptov(evictee->frame_address));
    frame_set_swap(evictee, swap_idx);
    lock_release(&swap_lock);
  } else {
    frame_set_filesys(evictee);
  }

  uintptr_t frame_address = evictee->frame_address;
  hash_delete(&frame_table, &evictee->elem);
  frame_destroy(&evictee->elem, NULL);
  palloc_free_page(ptov(frame_address));
}

/* Function: set_pinned()
 * ----------------------
 * Sets a given frame's pinned value to the given pin boolean
 * Param frame - address of the frame in question
 * Param pin   - the new pinned value about to be set
 */
void set_pinned(uintptr_t frame, bool pin) {
  struct frame_elem *e = frame_lookup(frame);
  if (e) {
    e->pinned = pin;
  }
}

/* Function: pin_frame()
 * ---------------------
 * Sets the pin value to be true for all pages starting from vaddr until size
 * Param vaddr - start of first page to be set to true
 * Param  size - number of bytes of pages about to be set to true
 */
void pin_frame(const void *vaddr, int size) {
  int index = size / PGSIZE;
  if (size % PGSIZE) index++;
  lock_acquire(&frame_lock);
  lock_acquire(&thread_current()->spt_lock);
  for (int i = 0; i < index; i++) {
    void *kpage_address = pagedir_get_page(thread_current()->pagedir,
                                           pg_round_down(vaddr) + i * PGSIZE);
    if (kpage_address == NULL) {
      struct spt_elem *e =
          spt_lookup(&thread_current()->spt, pg_round_down(vaddr) + i * PGSIZE);
      ASSERT(e);
      ASSERT(page_load(e));
      kpage_address = pagedir_get_page(thread_current()->pagedir,
                                       pg_round_down(vaddr) + i * PGSIZE);
    }
    set_pinned(vtop(kpage_address), true);
  }
  lock_release(&thread_current()->spt_lock);
  lock_release(&frame_lock);
}

/* Function: unpin_frame()
 * ---------------------
 * Sets the pin value to be false for all pages starting from vaddr until size
 * Param vaddr - start of first page to be set to false
 * Param  size - number of bytes of pages about to be set to false
 */
void unpin_frame(const void *vaddr, int size) {
  int index = size / PGSIZE;
  if (size % PGSIZE) index++;
  lock_acquire(&frame_lock);
  for (int i = 0; i < index; i++) {
    void *kpage_address = pagedir_get_page(thread_current()->pagedir,
                                           pg_round_down(vaddr) + i * PGSIZE);
    set_pinned(vtop(kpage_address), false);
  }
  lock_release(&frame_lock);
}
