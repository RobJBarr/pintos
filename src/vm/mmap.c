#include "vm/mmap.h"

#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"

/* Function: hash_mmap_file()
 * -------------------------
 * Creates a hash for a given MMAP table elem's hash elem using the
 * mmap id.
 * 
 * Param e   - mmap file hash elem
 * Param aux - UNUSED
 *
 * Returns   - hashed value of the mmap id
 */
unsigned hash_mmap_file(const struct hash_elem *e, void *aux UNUSED) {
  mapid_t id = (unsigned)hash_entry(e, struct mmap_file, elem)->id;
  return hash_int(id);
}

/* Function: mmap_file_compare()
 * -------------------------
 * Compares 2 mmap files based on their mmap id.
 *
 * Param a   - hash elem of the first mmap file to compare
 * Param b   - hash elem of the second mmap file to compare
 * Param aux - UNUSED
 *
 * Returns   - true if the first argument is smaller.
 */
bool mmap_file_compare(const struct hash_elem *a, const struct hash_elem *b,
                       void *aux UNUSED) {
  struct mmap_file *m_f1 = hash_entry(a, struct mmap_file, elem);
  struct mmap_file *m_f2 = hash_entry(b, struct mmap_file, elem);
  return m_f1->id < m_f2->id;
}

/* Function: mmap_file_destroy()
 * -------------------------
 * Destroy a mmap_file, writing back to memory if any of the
 * allocated pages has been changed.
 *
 * Param e   - hash elem of the mmap_file to destroy
 * Param aux - UNUSED
 */
void mmap_file_destroy(struct hash_elem *e, void *aux UNUSED) {
  struct thread *t = thread_current();
  struct mmap_file *m_f = hash_entry(e, struct mmap_file, elem);
  void *addr = m_f->vaddr;
  off_t file_length = m_f->file_length;

  /* Go through all the pages that are part of this file. */
  for (void *pg = addr; (int)pg < (int)addr + file_length; pg = pg + PGSIZE) {
    /* Check if the page is in the pagedir. */
    if (pagedir_get_page(t->pagedir, pg)) {
      /* If the dirty bit is set then write back. */
      if (pagedir_is_dirty(t->pagedir, pg)) {
        /* If the last page has less than PGSIZE bytes then we have to
         * discard the added zeroes by just writing the difference
         * between the current offset and the length of the file. */
        off_t bytes_write =
            pg + PGSIZE < addr + file_length ? PGSIZE : addr + file_length - pg;
        file_write_at(m_f->file, pg, bytes_write, pg - addr);
      }

      /* Remove from the page table and free page. */
      palloc_free_page(pagedir_get_page(t->pagedir, pg));
      pagedir_clear_page(t->pagedir, pg);
    }

    hash_delete(&t->spt, e);
  }

  file_close(m_f->file);
  free(m_f);
}

/* Function: new_mmap_file()
 * -------------------------
 * Create a new mmap_file given a virtual address, file pointer
 * and file_length (to avoid recalculation).
 * Param vaddr       - virtual address the memory mapped files starts at
 * Param file        - pointer to the opened file
 * Param file_length - length of the opened file
 *
 * Returns           - malloc'd mmap_file
 */
struct mmap_file *new_mmap_file(void *vaddr, struct file *file,
                                off_t file_length) {
  struct mmap_file *m_f = (struct mmap_file *)malloc(sizeof(struct mmap_file));
  m_f->id = thread_current()->next_mmap_id++;
  m_f->vaddr = vaddr;
  m_f->file = file;
  m_f->file_length = file_length;
  return m_f;
}

/* Function: lookup_mmap_file()
 * -------------------------
 * Lookup a mmap_file in the mmap_files hashmap of the
 * current thread.
 * Param map_id - mmap_file id to search for
 *
 * Returns      - Resulting mmap_file, NULL if not found
 */
struct mmap_file *lookup_mmap_file(int map_id) {
  struct mmap_file dummy_mmap;
  dummy_mmap.id = map_id;
  struct hash_elem *e =
      hash_find(&thread_current()->mmap_files, &dummy_mmap.elem);

  if (e == NULL) {
    return NULL;
  }

  return hash_entry(e, struct mmap_file, elem);
}
