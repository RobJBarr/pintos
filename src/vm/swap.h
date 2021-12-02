#ifndef VM_SWAP
#define VM_SWAP
#include <bitmap.h>

#include "devices/block.h"
#include "threads/synch.h"

extern struct lock swap_lock;

/* Initialisation and destruction */
void swap_init(void);
void swap_destroy(void);

/* Insertion and removal */
block_sector_t swap_insert(const void *address);
void swap_get_and_remove(block_sector_t idx, void *dest);

#endif
