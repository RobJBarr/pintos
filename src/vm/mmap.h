#ifndef VM_MMAP
#define VM_MMAP
#include <hash.h>

#include "lib/user/syscall.h"
#include "filesys/file.h"


/* The mmap_file is how the OS keep tracks of the memory mapped files opened
 * by a user process. These are stored in the hashmap mmap_files from the
 * thread struct. They are uniquely identified by their id and their main role
 * is to store the file the page is linked to so we write back to it when an
 * unmap happens. */
struct mmap_file {
  mapid_t id;            /* Unique identifier in the process. */
  void *vaddr;           /* Virtual address where the file starts. */
  struct file *file;     /* Pointer to the stored file. */
  off_t file_length;     /* Length of the file, to avoid recalculation. */
  struct hash_elem elem; /* Element used for inserting in the hash map. */
};

unsigned hash_mmap_file(const struct hash_elem *e, void *aux);
bool mmap_file_compare(const struct hash_elem *a, const struct hash_elem *b,
                       void *aux);
void mmap_file_destroy(struct hash_elem *e, void *aux);
struct mmap_file *new_mmap_file(void *vaddr, struct file *file,
                                off_t file_length);
struct mmap_file *lookup_mmap_file(int map_id);

#endif