#ifndef VM_FRAME
#define VM_FRAME
#include <hash.h>
#include <list.h>
#include <stdbool.h>
#include <stdint.h>

#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"

struct frame_elem {
  uintptr_t frame_address;   /* Physical address of the frame */
  struct list page_mappings; /* List of owners and their corresponding virtual
                                addresses */
  bool writable;             /* True if the frame contains writable data */
  bool is_file;              /* Boolean that is true if the page is a file */
  struct file *file; /* The corresponding file if this entry refers to a file.
                        Can be NULL */
  off_t ofs;         /* The offset within the file */
  struct hash_elem elem; /* Hash elem used to insert into the frame table */
  bool pinned;           /* Bool used for eviction algorithm */
};

struct page_mapping {
  struct list_elem
      elem;           /* List elem used to insert into the page_mappings list */
  void *page_address; /* The page address of the entry */
  struct thread *owner; /* The owner of the entry */
};

extern struct lock
    frame_lock; /* Lock used to synchronise accesses to the frame table */
extern struct hash frame_table; /* Frame table storing information about the
                                  pages currently in memory */

/* Init and destruction */
void frame_table_init(void);
void frame_table_destroy(void);
bool remove_from_owners(struct frame_elem *f);
void frame_destroy(struct hash_elem *e, void *aux UNUSED);

/* Allocation */
struct frame_elem *frame_create(void);
struct page_mapping *mapping_create(struct thread *t, void *page_address);

/* Lookups */
struct frame_elem *frame_lookup(uintptr_t frame_address);
struct frame_elem *frame_lookup_file(struct file *file, off_t ofs,
                                     bool writable);
bool frame_get_accessed(struct frame_elem *f);
bool frame_get_dirty(struct frame_elem *f);

/* Transitional functions */
void frame_unset_accessed(struct frame_elem *f);
void frame_set_swap(struct frame_elem *f, block_sector_t swap_idx);
void frame_set_filesys(struct frame_elem *f);

/* Eviction */
struct frame_elem *frame_to_evict(void);
void evict_frame(void);

/* Pinning Frames */
void set_pinned(uintptr_t frame, bool pin);
void pin_frame(const void *vaddr, int size);
void unpin_frame(const void *vaddr, int size);

#endif
