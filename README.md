# MPMalloc
<sub>**Note: MPMalloc is not a drop-in replacement for the system's default malloc since it doesn’t track the size of each allocated block. Size tracking will come as a macro option in the near-future.**</sub>  

## Overview

MPMalloc is a high-performance memory allocator written in C for Windows and Unix-like systems. Its design is reminiscent of TCMalloc, in that the heap is structured using a hierarchy of caches. Each thread thus keeps a local allocator for small objects and forwards large allocation requests to a shared structure. MPMalloc also takes inspiration from JEMalloc's chunks to arrive at a data structure creatively called the "block allocator", which is the main building block of the entire library. A block allocator is essentially a cache-aware bitmap allocator that supports serial allocation, serial deallocation _and_ concurrent deallocation. Due to how thread-local and thread-shared data are accessed, returning memory from a different thread to a block allocator is usually wait-free and, _sometimes_, lock-free.

## Compiler Support

Currently GCC, Clang and MSVC are supported.  

## Platform Support

MPMalloc has been tested on Windows 10 and FreeBSD (13.0-RELEASE-p3). It *should* also work on any Windows version that supports VirtualAlloc2 and on Linux systems.

## Core API

```c
mp_bool mp_init(const mp_init_options* options);
mp_bool mp_init_default();
mp_bool mp_enabled();
void mp_cleanup();
void mp_thread_init();
mp_bool mp_thread_enabled();
void mp_thread_cleanup();

size_t mp_size_class_count();
void mp_enumerate_size_classes(size_t* out_ptr);

void* mp_malloc(size_t size);
mp_bool mp_resize_sized(const void* ptr, size_t old_size, size_t new_size);
void* mp_realloc_sized(void* ptr, size_t old_size, size_t new_size);
void mp_free_sized(const void* ptr, size_t size);
size_t mp_round_size(size_t size);
size_t mp_min_alignment(size_t size);

#ifdef MP_LEGACY_COMPATIBLE
size_t mp_rounded_allocation_size_of(const void* ptr);
mp_bool mp_resize(const void* ptr, size_t new_size);
void* mp_realloc(void* ptr, size_t new_size);
void mp_free(const void* ptr);
#endif

void* mp_tcache_malloc(size_t size, mp_flags flags);
mp_bool mp_tcache_resize(const void* ptr, size_t old_size, size_t new_size, mp_flags flags);
void mp_tcache_free(const void* ptr, size_t size);
size_t mp_tcache_round_size(size_t size);
size_t mp_tcache_min_size();
size_t mp_tcache_max_size();

void* mp_lcache_malloc(size_t size, mp_flags flags);
mp_bool mp_lcache_resize(const void* ptr, size_t old_size, size_t new_size, mp_flags flags);
void mp_lcache_free(const void* ptr, size_t size);
size_t mp_lcache_round_size(size_t size);
size_t mp_lcache_min_size();
size_t mp_lcache_max_size();
void mp_lcache_usage_stats(mp_usage_stats* out_stats);

void* mp_persistent_malloc(size_t size);
void mp_persistent_cleanup();

void* mp_backend_malloc(size_t size);
mp_bool mp_backend_resize(const void* ptr, size_t old_size, size_t new_size);
void* mp_backend_realloc(void* ptr, size_t old_size, size_t new_size);
void mp_backend_free(const void* ptr, size_t size);
void mp_backend_purge(void* ptr, size_t size);
size_t mp_backend_required_alignment();

size_t mp_cache_line_size();
size_t mp_page_size();
size_t mp_large_page_size();
void* mp_lowest_address();
void* mp_highest_address();

void mp_debug_init(const mp_debug_options* options);
void mp_debug_init_default();
mp_bool mp_debug_enabled();
void mp_debug_message(const char* message, size_t size);
void mp_debug_warning(const char* message, size_t size);
void mp_debug_error(const char* message, size_t size);
mp_bool mp_debug_validate_memory(const void* ptr, size_t size);
mp_bool mp_debug_overflow_check(const void* ptr, size_t size);
```

## TODO
- Add a way to return unused block allocators (chunks) from the local TCache to the LCache.
- Give more options for malloc/free.
- Add support for aligned allocation.
- Add a mechanism for returning physical memory to the OS, via DiscardVirtualMemory/madvise.
- Add a mechanism for returning virtual memory addresses to the OS, via VirtualFree/munmap.  
- (Optional) Since small allocations rely on bitmask allocators, attempt to compact memory using a similar system to Emery Berger's MESH.
- (Optional) Attempt to achieve wait-freedom for certain free-list types.
