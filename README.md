# MPMalloc
<sub>**Note: MPMalloc is not a drop-in replacement for the system's default malloc since it doesn’t track the size of each allocated block. Size tracking will come as a macro option in the near-future.**</sub>  

## Overview

MPMalloc is a high-performance memory allocator written in C for Windows and Unix-like systems. Its design is reminiscent of TCMalloc, in that the heap is structured using a hierarchy of caches. Each thread thus keeps a local allocator for small objects and forwards large allocation requests to a shared structure. MPMalloc also takes inspiration from JEMalloc's chunks to arrive at a data structure creatively called the "block allocator", which is the main building block of the entire library. A block allocator is essentially a cache-aware bitmap allocator that supports serial allocation, serial deallocation _and_ concurrent deallocation. Due to how thread-local and thread-shared data are accessed, returning memory from a different thread to a block allocator is usually wait-free and, _sometimes_, lock-free.

## Compiler Support

Currently GCC, Clang and MSVC are supported.  

## Platform Support

MPMalloc has been tested on Windows 10 and FreeBSD (13.0-RELEASE-p3). It *should* also work on any Windows version that supports VirtualAlloc2 and on Linux systems.

## API

```c
MP_ATTR mp_bool				MP_CALL mp_init(const mp_init_options* options);
MP_ATTR mp_bool				MP_CALL mp_init_default();
MP_ATTR mp_bool				MP_CALL mp_enabled();
MP_ATTR void				MP_CALL mp_cleanup();
MP_ATTR void				MP_CALL mp_thread_init();
MP_ATTR mp_bool				MP_CALL mp_thread_enabled();
MP_ATTR void				MP_CALL mp_thread_cleanup();

MP_ATTR size_t				MP_CALL mp_size_class_count();
MP_ATTR void				MP_CALL mp_enumerate_size_classes(size_t* out_ptr);

MP_NODISCARD MP_ATTR void*	MP_CALL mp_malloc(size_t size);
MP_ATTR mp_bool				MP_CALL mp_resize_sized(const void* ptr, size_t old_size, size_t new_size);
MP_NODISCARD MP_ATTR void*	MP_CALL mp_realloc_sized(void* ptr, size_t old_size, size_t new_size);
MP_ATTR void				MP_CALL mp_free_sized(const void* ptr, size_t size);
MP_ATTR size_t				MP_CALL mp_round_size(size_t size);
MP_ATTR size_t				MP_CALL mp_min_alignment(size_t size);

#ifdef MP_LEGACY_COMPATIBLE
MP_ATTR size_t				MP_CALL mp_rounded_allocation_size_of(const void* ptr);
MP_ATTR mp_bool				MP_CALL mp_resize(const void* ptr, size_t new_size);
MP_NODISCARD MP_ATTR void*	MP_CALL mp_realloc(void* ptr, size_t new_size);
MP_ATTR void				MP_CALL mp_free(const void* ptr);
#endif

MP_NODISCARD MP_ATTR void*	MP_CALL mp_tcache_malloc(size_t size, mp_flags flags);
MP_ATTR mp_bool				MP_CALL mp_tcache_resize(const void* ptr, size_t old_size, size_t new_size, mp_flags flags);
MP_ATTR void				MP_CALL mp_tcache_free(const void* ptr, size_t size);
MP_ATTR size_t				MP_CALL mp_tcache_round_size(size_t size);
MP_ATTR size_t				MP_CALL mp_tcache_min_size();
MP_ATTR size_t				MP_CALL mp_tcache_max_size();

MP_NODISCARD MP_ATTR void*	MP_CALL mp_lcache_malloc(size_t size, mp_flags flags);
MP_ATTR mp_bool				MP_CALL mp_lcache_resize(const void* ptr, size_t old_size, size_t new_size, mp_flags flags);
MP_ATTR void				MP_CALL mp_lcache_free(const void* ptr, size_t size);
MP_ATTR size_t				MP_CALL mp_lcache_round_size(size_t size);
MP_ATTR size_t				MP_CALL mp_lcache_min_size();
MP_ATTR size_t				MP_CALL mp_lcache_max_size();
MP_ATTR void				MP_CALL mp_lcache_usage_stats(mp_usage_stats* out_stats);

MP_NODISCARD MP_ATTR void*	MP_CALL mp_persistent_malloc(size_t size);
MP_ATTR void				MP_CALL mp_persistent_cleanup();

MP_NODISCARD MP_ATTR void*	MP_CALL mp_backend_malloc(size_t size);
MP_ATTR mp_bool				MP_CALL mp_backend_resize(const void* ptr, size_t old_size, size_t new_size);
MP_ATTR void*				MP_CALL mp_backend_realloc(void* ptr, size_t old_size, size_t new_size);
MP_ATTR void				MP_CALL mp_backend_free(const void* ptr, size_t size);
MP_ATTR void				MP_CALL mp_backend_purge(void* ptr, size_t size);
MP_ATTR size_t				MP_CALL mp_backend_required_alignment();

MP_ATTR size_t				MP_CALL mp_cache_line_size();
MP_ATTR size_t				MP_CALL mp_page_size();
MP_ATTR size_t				MP_CALL mp_large_page_size();
MP_ATTR void*				MP_CALL mp_lowest_address();
MP_ATTR void*				MP_CALL mp_highest_address();

MP_ATTR void				MP_CALL mp_debug_init(const mp_debug_options* options);
MP_ATTR void				MP_CALL mp_debug_init_default();
MP_ATTR mp_bool				MP_CALL mp_debug_enabled();
MP_ATTR void				MP_CALL mp_debug_message(const char* message, size_t size);
MP_ATTR void				MP_CALL mp_debug_warning(const char* message, size_t size);
MP_ATTR void				MP_CALL mp_debug_error(const char* message, size_t size);
MP_ATTR mp_bool				MP_CALL mp_debug_validate_memory(const void* ptr, size_t size);
MP_ATTR mp_bool				MP_CALL mp_debug_overflow_check(const void* ptr, size_t size);
```

## TODO
- Add a way to return unused block allocators (chunks) from the local TCache to the LCache.
- Give more options for malloc/free.
- Add support for aligned allocation.
- Add a mechanism for returning physical memory to the OS, via DiscardVirtualMemory/madvise.
- Add a mechanism for returning virtual memory addresses to the OS, via VirtualFree/munmap.  
- (Optional) Since small allocations rely on bitmask allocators, attempt to compact memory using a similar system to Emery Berger's MESH.
- (Optional) Attempt to achieve wait-freedom for certain free-list types.
