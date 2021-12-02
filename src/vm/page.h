#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"

enum data_type {
  FILE_SYS, /* Data on file system. */
  SWAP,     /* Data in the swap. */
  PRESENT   /* Data present in memeory. */
};

struct filesys_data {
  struct file *file;               /* Name of file in question */
  off_t offset;                    /* The offset into the file */
  uint32_t read_bytes, zero_bytes; /* Number of bytes to be read/zeroed */
};

struct spt_elem {
  void *uvaddr; /* Virtual user address of page */

  enum data_type type; /* Type of the data */

  /* If it is FILE_SYS data */
  struct filesys_data *file_data; /* Data about the file */
  bool writable;                  /* If the page is writable */
  bool executable;                /* If the page is executable */

  /* If it is SWAP data */
  block_sector_t swap_index; /* Swap index for the swap table */

  struct hash_elem elem; /* Hash used to insert into SPT */
};

/* Hash interface functions */
unsigned hash_spt_elem(const struct hash_elem *e, void *aux);
bool spt_compare(const struct hash_elem *a, const struct hash_elem *b,
                 void *aux);
void spt_elem_destroy(struct hash_elem *e, void *aux);

/* Loading and unloading pages */
bool page_load(struct spt_elem *e);
bool load_file_sys(struct spt_elem *e);
void page_unload(struct spt_elem *);

/* Lookups */
struct spt_elem *spt_lookup(struct hash *spt, void *uvaddr);

/* New pages */
struct spt_elem *new_file_page(void *uvaddr, struct file *file, off_t offset,
                               uint32_t read_bytes, uint32_t zero_bytes,
                               bool writable, bool executable);
struct spt_elem *new_present_page(void *uvaddr);

/* Transitional functions */
bool set_swap(struct thread *t, void *uvaddr, block_sector_t swap_index);

/* Stack growth */
bool stack_grow(void *);
#endif
