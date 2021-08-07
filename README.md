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

void* mp_malloc(size_t size);
mp_bool mp_resize_sized(const void* ptr, size_t old_size, size_t new_size);
void* mp_realloc_sized(void* ptr, size_t old_size, size_t new_size);
void mp_free_sized(const void* ptr, size_t size);
size_t mp_round_size(size_t size);
size_t mp_min_alignment(size_t size);

#ifdef MP_LEGACY_COMPATIBLE
size_t mp_allocation_size_of(const void* ptr);
mp_bool mp_resize(const void* ptr, size_t new_size);
void* mp_realloc(void* ptr, size_t new_size);
void mp_free(const void* ptr);
#endif
```

## TODO
- Add a way to return unused block allocators (chunks) from the local TCache to the LCache.
- Give more options for malloc/free.
- Add support for aligned allocation.
- Add a mechanism for returning physical memory to the OS, via DiscardVirtualMemory/madvise.
- Add a mechanism for returning virtual memory addresses to the OS, via VirtualFree/munmap.  
- (Optional) Since small allocations rely on bitmask allocators, attempt to compact memory using a similar system to Emery Berger's MESH.
- (Optional) Attempt to achieve wait-freedom for certain free-list types.
