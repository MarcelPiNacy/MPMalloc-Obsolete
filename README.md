# MPMM

## Compiler Support

Currently GCC, Clang and MSVC are supported.  

## Platform Support

MPMM has been tested on Windows 10. It *might* work on Linux.

## Overview

MPMM is a high-performance memory allocator written in C for Windows and Linux systems.  
The main goals of this project are:
-	Eliminate synchronization events and minimize contention.
-	Experiment with highly cache aware data structures.
-	Avoid heap size blowup.
-	Improve on the classic malloc API.  

MPMM’s design is reminiscent of Google’s TCMalloc, in that the heap is structured using a hierarchy of caches. Each thread thus keeps a local allocator for small objects and delegates larger allocations to a central heap. MPMM’s large size threshold, internally called “chunk size”, is proportional to the system’s virtual page size and the processor’s cache line size. For x86/x64 systems with 4KiB-sized pages, this value happens to match 2MiB, which is usually also the large page size.  
Note: MPMM is not a drop-in replacement for malloc since it doesn’t track the size of each allocated block. A malloc-compatible variant will come as a separate library in the near-future.

## Thread Caches
MPMM’s thread caches consists of one free-list per size-class. The twist is that each free-list doesn’t store individual objects, but instead chunk-aligned bitmap allocators, where the bitmap size matches the cache line size. In the rare case that one of the allocators runs out of free objects, the head of the free-list is discarded and “leaked”. On deallocation, the corresponding header can be found using pointer arithmetic and recovered. For cross-thread deallocations, like in a producer-consumer scenario, these allocators keep a separate atomic bitmap.
Tiny allocations, objects smaller than the page size, use “intrusive block allocators”, which are bitmap allocators where the first few blocks are reserved for storing the necessary metadata. Small allocations instead associate the chunk address with the metadata using a regular array in 32-bit systems. For 64-bit systems a 3-level digital tree is used, where the first level is allocated statically.

## Large Cache
The large cache uses a more conventional approach: it consists of a global array/digital tree that maps size classes to free-lists.

## Backend Allocator
If MPMM runs out of memory, by default it will request more memory to the system (mmap/VirtualAlloc2). However, the user can also provide their own set of callbacks at startup.

## API

```c
void        mpmm_init_info_default(mpmm_init_options* out_options);
void        mpmm_trim_options_default(mpmm_trim_options* out_options);
void        mpmm_debugger_options_default(mpmm_debugger_options* out_options);

void        mpmm_init(const mpmm_init_options* options);
mpmm_bool   mpmm_is_initialized();
void        mpmm_cleanup();

void        mpmm_thread_init();
void        mpmm_thread_cleanup();

void        mpmm_stats(mpmm_mem_stats* out_stats);
void        mpmm_params(mpmm_global_params* out_params);

void*	    mpmm_malloc(size_t size);
mpmm_bool   mpmm_resize(void* ptr, size_t old_size, size_t new_size);
void*	    mpmm_realloc(void* ptr, size_t old_size, size_t new_size);
void        mpmm_free(void* ptr, size_t size);
size_t      mpmm_round_size(size_t size);
size_t      mpmm_purge(mpmm_flags flags, void* param);
size_t      mpmm_trim(const mpmm_trim_options* options);

void*	    mpmm_tcache_malloc(size_t size, mpmm_flags flags);
void        mpmm_tcache_free(void* ptr, size_t size);
size_t      mpmm_tcache_round_size(size_t size);
size_t      mpmm_tcache_flush(mpmm_flags flags, void* param);
size_t      mpmm_tcache_min_size();
size_t      mpmm_tcache_max_size();

void*    	mpmm_lcache_malloc(size_t size, mpmm_flags flags);
void        mpmm_lcache_free(void* ptr, size_t size);
size_t      mpmm_lcache_round_size(size_t size);
size_t      mpmm_lcache_flush(mpmm_flags flags, void* param);
size_t      mpmm_lcache_min_size();
size_t      mpmm_lcache_max_size();

void*	    mpmm_persistent_malloc(size_t size);
void        mpmm_persistent_cleanup();

size_t      mpmm_backend_required_alignment();
void*	    mpmm_backend_malloc(size_t size);
mpmm_bool   mpmm_backend_resize(void* ptr, size_t old_size, size_t new_size);
void        mpmm_backend_free(void* ptr, size_t size);
void        mpmm_backend_purge(void* ptr, size_t size);

void        mpmm_debugger_init(const mpmm_debugger_options* options);
mpmm_bool   mpmm_debugger_enabled();
void        mpmm_debugger_message(const char* message, size_t size);
void        mpmm_debugger_warning(const char* message, size_t size);
void        mpmm_debugger_error(const char* message, size_t size);
```