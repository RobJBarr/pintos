#include "vm/swap.h"

#include <debug.h>

#include "threads/vaddr.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct bitmap *swap_used;
static struct block *swap_table;
struct lock swap_lock;

/* Function: swap_init()
 * --------------------
 * Initialises the swap block, bitmap and lock
 */
void swap_init(void) {
  lock_init(&swap_lock);
  swap_table = block_get_role(BLOCK_SWAP);
  swap_used =
      bitmap_create(block_size(swap_table) * BLOCK_SECTOR_SIZE / PGSIZE);
}

/* Function: swap_insert()
 * ----------------------
 * Finds a space in the swap and writes the given address at this
 * point. If no space is available in swap, panic the kernel.
 * Param address - the virtual page address to write to swap.
 *
 * Return        - the sector of swap which the address was written to. This
 *                 has to be stored in order to access the address again.
 *
 * NOTE you must acquire the swap_lock before calling this function
 */
block_sector_t swap_insert(const void *address) {
  size_t page_idx = bitmap_scan_and_flip(swap_used, 0, 1, false);

  if (page_idx == BITMAP_ERROR) {
    PANIC("Swap partition ran out of memory");
  }

  block_sector_t sector = SECTORS_PER_PAGE * page_idx;
  for (int i = 0; i < SECTORS_PER_PAGE; ++i) {
    block_write(swap_table, sector + i, address + BLOCK_SECTOR_SIZE * i);
  }
  return sector;
}

/* Function: swap_get_and_remove()
 * ------------------------------
 * Reads the swap at the given sector location and writes this
 * into dest.
 * Param sector - the sector of swap to read
 * Param dest   - the location in which to store the result of the
 *                swap read.
 *
 * NOTE you must acquire the swap_lock before calling this function.
 */
void swap_get_and_remove(block_sector_t sector, void *dest) {
  size_t page_idx = sector / SECTORS_PER_PAGE;

  if (bitmap_test(swap_used, page_idx)) {
    bitmap_flip(swap_used, page_idx);

    if (dest) {
      for (int i = 0; i < SECTORS_PER_PAGE; ++i) {
        block_read(swap_table, sector + i, dest + BLOCK_SECTOR_SIZE * i);
      }
    }
  } else {
    // page not there
    PANIC("Invalid swap access");
  }
}

/* Function: swap_destroy()
 * -----------------------
 * Deallocates where necessary the resources used by the swap.
 */
void swap_destroy(void) { bitmap_destroy(swap_used); }
