# MPMalloc

## Compiler Support

Currently GCC, Clang and MSVC are supported.  

## Platform Support

MPMalloc has been tested on Windows 10. It *might* work on Linux.

## Overview

MPMalloc is a high-performance memory allocator written in C for Windows and Linux systems.  
The main goals of this project are:
-	Eliminate synchronization events and minimize contention.
-	Experiment with highly cache aware data structures.
-	Avoid heap size blowup.
-	Improve on the classic malloc API.  

MPMalloc’s design is reminiscent of Google’s TCMalloc, in that the heap is structured using a hierarchy of caches. Each thread thus keeps a local allocator for small objects and delegates larger allocations to a central heap. MPMalloc’s large size threshold, internally called “chunk size”, is proportional to the system’s virtual page size and the processor’s cache line size. For x86/x64 systems with 4KiB-sized pages, this value happens to match 2MiB, which is usually also the large page size.  
<sub>**Note: MPMalloc is not a drop-in replacement for malloc since it doesn’t track the size of each allocated block. A malloc-compatible variant will come as a separate library in the near-future.**</sub>

## Thread Caches
MPMalloc’s thread caches consists of one free-list per size-class. The twist is that each free-list doesn’t store individual objects, but instead chunk-aligned bitmap allocators, where the bitmap size matches the cache line size. In the rare case that one of the allocators runs out of free objects, the head of the free-list is discarded and “leaked”. On deallocation, the corresponding header can be found using pointer arithmetic and recovered. For cross-thread deallocations, like in a producer-consumer scenario, these allocators keep a separate atomic bitmap.
Tiny allocations, objects smaller than the page size, use “intrusive block allocators”, which are bitmap allocators where the first few blocks are reserved for storing the necessary metadata. Small allocations instead associate the chunk address with the metadata using a regular array in 32-bit systems. For 64-bit systems a 3-level digital tree is used, where the first level is allocated statically.

## Large Cache
The large cache uses a more conventional approach: it consists of a global array/digital tree that maps size classes to free-lists.

## Backend Allocator
If MPMalloc runs out of memory, by default it will request more memory to the system (mmap/VirtualAlloc2). However, the user can also provide their own set of callbacks at startup.

## API

```c
void				mp_init(const mp_init_options* options);
void				mp_init_default();
mp_bool				mp_enabled();
void				mp_cleanup();
void				mp_thread_init();
mp_bool				mp_thread_enabled();
void				mp_thread_cleanup();

void*	            mp_malloc(size_t size);
mp_bool				mp_resize(void* ptr, size_t old_size, size_t new_size);
void*	            mp_realloc(void* ptr, size_t old_size, size_t new_size);
void				mp_free(void* ptr, size_t size);
size_t				mp_round_size(size_t size);

void*	            mp_tcache_malloc(size_t size, mp_flags flags);
mp_bool				mp_tcache_resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags);
void				mp_tcache_free(void* ptr, size_t size);
size_t				mp_tcache_round_size(size_t size);
size_t				mp_tcache_min_size();
size_t				mp_tcache_max_size();

void*	            mp_lcache_malloc(size_t size, mp_flags flags);
mp_bool				mp_lcache_resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags);
void				mp_lcache_free(void* ptr, size_t size);
size_t				mp_lcache_round_size(size_t size);
size_t				mp_lcache_min_size();
size_t				mp_lcache_max_size();

void*	            mp_persistent_malloc(size_t size);
void				mp_persistent_cleanup();

void*	            mp_backend_malloc(size_t size);
mp_bool				mp_backend_resize(void* ptr, size_t old_size, size_t new_size);
void				mp_backend_free(void* ptr, size_t size);
void				mp_backend_purge(void* ptr, size_t size);
size_t				mp_backend_required_alignment();

void				mp_debug_init(const mp_debug_options* options);
void				mp_debug_init_default();
mp_bool				mp_debug_enabled();
void				mp_debug_message(const char* message, size_t size);
void				mp_debug_warning(const char* message, size_t size);
void				mp_debug_error(const char* message, size_t size);
mp_bool				mp_debug_validate_memory(const void* ptr, size_t size);
mp_bool				mp_debug_overflow_check(const void* ptr, size_t size);
```

## TODO
- Fix strange bug when freeing certain size classes.
- Fix ABA issue with recover_list's push function.
- Add a way to return unused block allocators (chunks) from the local TCache to the LCache.
- Give more options for malloc/free.
- Add support for aligned allocation.
- Add a mechanism for returning physical memory to the OS, via DiscardVirtualMemory/madvise.
- Add a mechanism for returning virtual memory addresses to the OS, via VirtualFree/munmap.  
- Add support for huge pages.
- (Optional) Since small allocations rely on bitmask allocators, attempt to compact memory using a similar system to Emery Berger's MESH.
- (Optional) Attempt to achieve wait-freedom for certain cases.
