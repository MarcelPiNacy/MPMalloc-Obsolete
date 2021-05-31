/*
	Copyright (C) 2021 Marcel Pi Nacy

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

// ================================================================
//	HELP
// ================================================================
/*
1. Macros
	- MP_DEBUG:
		Enabled if _DEBUG is defined and NDEBUG is not.
		Enables the internal debugger, substitutes assume statements with assertions, adds overflow checks and fills allocations with garbage values.

	- MP_CALL:
		Used to override the calling convention of the public functions of MPMalloc.

	- MP_ATTR:
		Used to add custom attributes to the public functions of MPMalloc.

	- MP_PTR:
		Used to override the calling convention of function pointers, such as backend allocator callbacks.

	- MP_CACHE_LINE_SIZE:
		Specifies the cache line size of the target platform, which affects the rate at which MPMalloc requests memory to the backend/OS.
		Currently only values of 32, 64 and 128 are supported.

	- MP_JUNK_VALUE:
		Used to memset allocations when MP_DEBUG is defined.

	- MP_CHECK_OVERFLOW:
		Enables overflow checks on free. Essentially appends "MP_REDZONE_SIZE" extra bytes to each allocation and memsets this range with "MP_REDZONE_VALUE".

	- MP_REDZONE_SIZE:
		The number of redzone bytes to append to each allocation.

	- MP_REDZONE_VALUE:
		The value to which redzones are initialized.

	- MP_NODISCARD:
		Defined to [[nodiscard]] if this C++ attribute is available.

	- MP_LARGE_PAGE_SUPPORT:
		If defined, includes the necessary system headers required for using large pages.
		MP_INIT_ENABLE_LARGE_PAGES must still be passed to mp_init to actually enable large pages.

	- MP_PAGE_MESHING_SUPPORT:
		If defined, includes the necessary system headers required for meshing pages.
		MP_INIT_ENABLE_LARGE_PAGES must still be passed to mp_init to actually enable large pages.

	- MP_STRICT_CHUNK_FREELIST:
		By default, MPMalloc's lock-free freelist for chunks uses the lower bits of the node pointers as generation counters to avoid ABA issues.
		Since MPMalloc doesn't support page sizes smaller than 4KiB and cache line sizes smaller than 32 bytes, the minimum chunk size possible is 2^20.
		This means that unless the number of running threads accessing a single free-list exceeds this value (minus one), ABA-related bugs aren't possible.
		Defining this turns these freelists into CMPXCHG16B-based ones, which is much slower but it's safer.
		Unless the number of threads can exceed 2^32 or 2^64...
*/

#ifndef MP_INCLUDED
#define MP_INCLUDED

#include <stdint.h>
#include <stddef.h>

#ifdef __linux__
#define MP_TARGET_LINUX
#elif defined(_WIN32)
#define MP_TARGET_WINDOWS
#else
#error "MPMALLOC: UNSUPPORTED TARGET OPERATING SYSTEM"
#endif

#if !defined(MP_DEBUG) && (defined(_DEBUG) || !defined(NDEBUG))
#define MP_DEBUG
#endif

#ifndef MP_CALL
#define MP_CALL
#endif

#ifndef MP_ATTR
#define MP_ATTR
#endif

#ifndef MP_PTR
#define MP_PTR
#endif

#ifndef MP_CACHE_LINE_SIZE
#define MP_CACHE_LINE_SIZE 64
#else
#if (MP_CACHE_LINE_SIZE != 32) && (MP_CACHE_LINE_SIZE != 64) && (MP_CACHE_LINE_SIZE != 128)
#error "MPMALLOC: Error, MP_CACHE_LINE_SIZE must be equal to 32, 64 or 128."
#endif
#endif

#if defined(MP_DEBUG) && !defined(MP_JUNK_VALUE)
#define MP_JUNK_VALUE 0xcd
#endif

#ifdef MP_DEBUG
#define MP_CHECK_OVERFLOW
#endif

#if !defined(MP_REDZONE_SIZE) && defined(MP_CHECK_OVERFLOW)
#define MP_REDZONE_SIZE sizeof(size_t)
#endif

#if !defined(MP_REDZONE_VALUE) && defined(MP_CHECK_OVERFLOW)
#define MP_REDZONE_VALUE 0xab
#endif

#ifndef MP_NODISCARD
#define MP_NODISCARD
#ifdef __cplusplus
#if __cplusplus >= 201703L
#undef MP_NODISCARD
#define MP_NODISCARD [[nodiscard]]
#endif
#endif
#endif

#ifdef __cplusplus
typedef bool mp_bool;
#define MP_EXTERN_C_BEGIN extern "C" {
#define MP_EXTERN_C_END }
#else
typedef _Bool mp_bool;
#define MP_EXTERN_C_BEGIN
#define MP_EXTERN_C_END
#endif

enum { MP_FALSE, MP_TRUE };

MP_EXTERN_C_BEGIN
typedef enum mp_init_flag_bits
{
	MP_INIT_ENABLE_PAGE_MESHING = 1U << 30,
	MP_INIT_ENABLE_LARGE_PAGES = 1U << 31
} mp_init_flag_bits;

typedef uint32_t mp_init_flags;

typedef enum mp_malloc_flag_bits
{
	MP_NO_FALLBACK = 1U,
	MP_NO_SYSCALL = 2U,
	MP_NO_ATOMICS = 4U,
} mp_malloc_flag_bits;

typedef uint32_t mp_flags;

typedef mp_bool(MP_PTR* mp_fn_init)(const struct mp_init_options*);
typedef void(MP_PTR* mp_fn_cleanup)();
typedef void*(MP_PTR* mp_fn_malloc)(size_t size);
typedef mp_bool(MP_PTR* mp_fn_resize)(void* ptr, size_t old_size, size_t new_size);
typedef void*(MP_PTR* mp_fn_realloc)(void* ptr, size_t old_size, size_t new_size);
typedef void(MP_PTR* mp_fn_free)(void* ptr, size_t size);
typedef void(MP_PTR* mp_fn_purge)(void* ptr, size_t size);
typedef void(MP_PTR *mp_fn_debug_message)(void* context, const char* message, size_t size);
typedef void(MP_PTR *mp_fn_debug_warning)(void* context, const char* message, size_t size);
typedef void(MP_PTR *mp_fn_debug_error)(void* context, const char* message, size_t size);

typedef struct mp_backend_options
{
	mp_fn_init init;
	mp_fn_cleanup cleanup;
	mp_fn_malloc malloc;
	mp_fn_resize resize;
	mp_fn_free free;
	mp_fn_purge purge;
} mp_backend_options;

typedef struct mp_init_options
{
	mp_init_flags flags;
	const mp_backend_options* backend;
} mp_init_options;

typedef struct mp_heap_stats
{
	size_t malloc_count;
	size_t free_count;
	size_t active_memory;
	size_t total_memory;
	size_t peak_memory;
} mp_heap_stats;

typedef struct mp_debug_options
{
	void* context;
	mp_fn_debug_message message;
	mp_fn_debug_warning warning;
	mp_fn_debug_error error;
} mp_debug_options;

typedef struct mp_param_list
{
	size_t alignment;
	mp_malloc_flag_bits flags;
} mp_param_list;

MP_ATTR mp_bool				MP_CALL mp_init(const mp_init_options* options);
MP_ATTR mp_bool				MP_CALL mp_init_default();
MP_ATTR mp_bool				MP_CALL mp_enabled();
MP_ATTR void				MP_CALL mp_cleanup();
MP_ATTR void				MP_CALL mp_thread_init();
MP_ATTR mp_bool				MP_CALL mp_thread_enabled();
MP_ATTR void				MP_CALL mp_thread_cleanup();

MP_NODISCARD MP_ATTR void*	MP_CALL mp_malloc(size_t size);
MP_ATTR mp_bool				MP_CALL mp_resize_sized(void* ptr, size_t old_size, size_t new_size);
MP_NODISCARD MP_ATTR void*	MP_CALL mp_realloc_sized(void* ptr, size_t old_size, size_t new_size);
MP_ATTR void				MP_CALL mp_free_sized(void* ptr, size_t size);

MP_ATTR size_t				MP_CALL mp_round_size(size_t size);

#ifdef MP_LEGACY_COMPATIBLE
MP_ATTR size_t				MP_CALL mp_block_size_of(void* ptr);
MP_ATTR mp_bool				MP_CALL mp_resize(void* ptr, size_t new_size);
MP_NODISCARD MP_ATTR void*	MP_CALL mp_realloc(void* ptr, size_t new_size);
MP_ATTR void				MP_CALL mp_free(void* ptr);
#endif

MP_NODISCARD MP_ATTR void*	MP_CALL mp_tcache_malloc(size_t size, mp_flags flags);
MP_ATTR mp_bool				MP_CALL mp_tcache_resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags);
MP_ATTR void				MP_CALL mp_tcache_free(void* ptr, size_t size);
MP_ATTR size_t				MP_CALL mp_tcache_round_size(size_t size);
MP_ATTR size_t				MP_CALL mp_tcache_min_size();
MP_ATTR size_t				MP_CALL mp_tcache_max_size();

MP_NODISCARD MP_ATTR void*	MP_CALL mp_lcache_malloc(size_t size, mp_flags flags);
MP_ATTR mp_bool				MP_CALL mp_lcache_resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags);
MP_ATTR void				MP_CALL mp_lcache_free(void* ptr, size_t size);
MP_ATTR size_t				MP_CALL mp_lcache_round_size(size_t size);
MP_ATTR size_t				MP_CALL mp_lcache_min_size();
MP_ATTR size_t				MP_CALL mp_lcache_max_size();

MP_NODISCARD MP_ATTR void*	MP_CALL mp_persistent_malloc(size_t size);
MP_ATTR void				MP_CALL mp_persistent_cleanup();

MP_NODISCARD MP_ATTR void*	MP_CALL mp_backend_malloc(size_t size);
MP_ATTR mp_bool				MP_CALL mp_backend_resize(void* ptr, size_t old_size, size_t new_size);
MP_ATTR void				MP_CALL mp_backend_free(void* ptr, size_t size);
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
MP_EXTERN_C_END



#ifdef MP_IMPLEMENTATION
#ifdef __cplusplus
#define MP_STATIC_ASSERT(EXPRESSION, MESSAGE) static_assert(EXPRESSION, MESSAGE)
#else
#define MP_STATIC_ASSERT(EXPRESSION, MESSAGE) _Static_assert(EXPRESSION, MESSAGE)
#endif
#if UINT32_MAX == UINTPTR_MAX
#define MP_32BIT
#define MP_PTR_SIZE 4
#define MP_PTR_SIZE_MASK 3
#define MP_PTR_SIZE_LOG2 2
#define MP_PTR_BITS 32
#define MP_PTR_BITS_MASK 31
#define MP_PTR_BITS_LOG2 5
#define MP_DPTR_SIZE 8
#else
#define MP_64BIT
#define MP_PTR_SIZE 8
#define MP_PTR_SIZE_MASK 7
#define MP_PTR_SIZE_LOG2 3
#define MP_PTR_BITS 64
#define MP_PTR_BITS_MASK 63
#define MP_PTR_BITS_LOG2 6
#define MP_DPTR_SIZE 16
#endif
#ifdef MP_CHECK_OVERFLOW
#define MP_SIZE_WITH_REDZONE(K) ((K) + MP_REDZONE_SIZE)
#else
#define MP_SIZE_WITH_REDZONE(K) (K)
#endif
#ifdef MP_DEBUG
#define MP_DEBUG_JUNK_FILL(P, K) MP_UNLIKELY_IF((P) != NULL) (void)memset((P), MP_JUNK_VALUE, (K))
#else
#define MP_DEBUG_JUNK_FILL(P, K)
#endif
#define MP_ALIGN_FLOOR_MASK(VALUE, MASK) ((VALUE) & ~(MASK))
#define MP_ALIGN_CEIL_MASK(VALUE, MASK) ((VALUE + (MASK)) & ~(MASK))
#define MP_ALIGN_FLOOR(VALUE, ALIGNMENT) MP_ALIGN_FLOOR_MASK(VALUE, (ALIGNMENT) - 1)
#define MP_ALIGN_CEIL(VALUE, ALIGNMENT) MP_ALIGN_CEIL_MASK(VALUE, (ALIGNMENT) - 1)
#define MP_OPTIONAL_U8(VALUE, CONDITION) ((uint8_t)(VALUE) & (uint8_t)-(int8_t)(CONDITION))
#define MP_SELECT_U8(CONDITION, ON_TRUE, ON_FALSE) (MP_OPTIONAL(ON_TRUE, (CONDITION)) | MP_OPTIONAL(ON_FALSE, !(CONDITION)))
#define MP_OPTIONAL(VALUE, CONDITION) ((size_t)(VALUE) & (size_t)-(ptrdiff_t)(CONDITION))
#define MP_SELECT(CONDITION, ON_TRUE, ON_FALSE) (MP_OPTIONAL(ON_TRUE, (CONDITION)) | MP_OPTIONAL(ON_FALSE, !(CONDITION)))
#define MP_IS_ALIGNED(PTR, ALIGNMENT) (((size_t)(PTR) & ((size_t)(ALIGNMENT) - (size_t)1)) == 0)
#ifdef MP_TARGET_LINUX
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#ifdef MP_LARGE_PAGE_SUPPORT
#include <hugetlbfs.h>
#endif
#elif defined(MP_TARGET_WINDOWS)
#include <Windows.h>
#if defined(MP_LARGE_PAGE_SUPPORT) || defined(MP_PAGE_MESHING_SUPPORT)
#include <ntsecapi.h>
#endif
#else
#error "MPMALLOC: UNSUPPORTED TARGET OPERATING SYSTEM"
#endif

#if defined(__clang__) || defined(__GNUC__)
#define MP_CLANG_OR_GCC
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define MP_SPIN_LOOP for (;; __builtin_ia32_pause())
#elif defined(__arm__)
#define MP_SPIN_LOOP for (;; __yield())
#elif defined(__POWERPC__)
#define MP_SPIN_LOOP for (;; asm volatile("or 31,31,31"))
#else
#define MP_SPIN_LOOP for (;;)
#endif
#define MP_ALIGNAS(SIZE) __attribute__((aligned((SIZE))))
#define MP_TLS __thread
#define MP_PURE __attribute__((pure))
#define MP_ULTRAPURE __attribute__((const))
#define MP_PREFETCH(PTR) __builtin_prefetch((PTR), 1, 3)
#define MP_EXPECT(CONDITION, VALUE) __builtin_expect((long)(CONDITION), (VALUE))
#define MP_LIKELY_IF(CONDITION) if (MP_EXPECT(CONDITION, MP_TRUE))
#define MP_UNLIKELY_IF(CONDITION) if (MP_EXPECT(CONDITION, MP_FALSE))
#define MP_POPCOUNT_32(MASK) __builtin_popcount((MASK))
#define MP_POPCOUNT_64(MASK) __builtin_popcountll((MASK))
#define MP_CTZ_32(MASK) __builtin_ctz((MASK))
#define MP_CTZ_64(MASK) __builtin_ctzll((MASK))
#define MP_CLZ_32(MASK) __builtin_clz((MASK))
#define MP_CLZ_64(MASK) __builtin_clzll((MASK))
#define MP_ROL_32(MASK, COUNT) _rotl((MASK), (COUNT))
#define MP_ROR_32(MASK, COUNT) _rotr((MASK), (COUNT))
#define MP_ROL_64(MASK, COUNT) _rotl64((MASK), (COUNT))
#define MP_ROR_64(MASK, COUNT) _rotr64((MASK), (COUNT))
#ifdef __SSE2__
#define MP_HAS_SSE2
#endif
#ifdef __AVX__
#define MP_HAS_AVX
#endif
#ifdef __AVX2__
#define MP_HAS_AVX2
#endif
#ifdef __AVX512F__
#define MP_HAS_AVX512F
#endif
#ifdef MP_DEBUG
#define MP_INLINE_ALWAYS
#define MP_INLINE_NEVER
#else
#define MP_INLINE_ALWAYS __attribute__((always_inline))
#define MP_INLINE_NEVER __attribute__((noinline))
#endif
#define MP_ASSUME(EXPRESSION) __builtin_assume((EXPRESSION))
#elif defined(_MSC_VER) || defined(_MSVC_LANG)
#define MP_MSVC
#include <intrin.h>
#if defined(_M_X64) || defined(_M_IX86)
#define MP_SPIN_LOOP for (;; _mm_pause())
#define MP_PREFETCH(PTR) _mm_prefetch((const CHAR*)(PTR), _MM_HINT_T0)
#elif defined(_M_ARM)
#define MP_SPIN_LOOP for (;; __yield())
#define MP_PREFETCH(PTR) __prefetch((const CHAR*)(PTR))
#elif defined(_M_PPC)
#define MP_SPIN_LOOP for (;;)
#define MP_PREFETCH(PTR)
#else
#define MP_SPIN_LOOP for (;;)
#define MP_PREFETCH(PTR)
#endif
#define MP_ALIGNAS(SIZE) __declspec(align(SIZE))
#define MP_TLS __declspec(thread)
#define MP_PURE __declspec(noalias)
#define MP_ULTRAPURE MP_PURE
#define MP_EXPECT(CONDITION, VALUE) (CONDITION)
#define MP_LIKELY_IF(CONDITION) if ((CONDITION))
#define MP_UNLIKELY_IF(CONDITION) if ((CONDITION))
#ifdef __AVX__
#define MP_HAS_SSE2
#define MP_HAS_AVX
#endif
#ifdef __AVX2__
#define MP_HAS_AVX2
#endif
#ifdef __AVX512F__
#define MP_HAS_AVX512F
#endif
#ifdef _M_ARM
#define MP_POPCOUNT_32(MASK) (uint_fast8_t)_CountOneBits((MASK))
#define MP_POPCOUNT_64(MASK) (uint_fast8_t)_CountOneBits64((MASK))
#define MP_CTZ_32(MASK) (uint_fast8_t)_CountLeadingZeros(_arm_rbit((MASK)))
#define MP_CTZ_64(MASK) (uint_fast8_t)_CountLeadingZeros64((((uint64_t)_arm_rbit((uint32_t)(MASK))) << 32) | (uint64_t)_arm_rbit(((uint32_t)(MASK)) >> 32))
#define MP_CLZ_32(MASK) (uint_fast8_t)_CountLeadingZeros((MASK))
#define MP_CLZ_64(MASK) (uint_fast8_t)_CountLeadingZeros64((MASK))
#else
#define MP_POPCOUNT_32(MASK) (uint_fast8_t)__popcnt((MASK))
#define MP_POPCOUNT_64(MASK) (uint_fast8_t)__popcnt64((MASK))
#define MP_CTZ_32(MASK) (uint_fast8_t)_tzcnt_u32((MASK))
#define MP_CTZ_64(MASK) (uint_fast8_t)_tzcnt_u64((MASK))
#define MP_CLZ_32(MASK) (uint_fast8_t)_lzcnt_u32((MASK))
#define MP_CLZ_64(MASK) (uint_fast8_t)_lzcnt_u64((MASK))
#endif
#define MP_ROL_32(MASK, COUNT) _rotl((MASK), (COUNT))
#define MP_ROR_32(MASK, COUNT) _rotr((MASK), (COUNT))
#define MP_ROL_64(MASK, COUNT) _rotl64((MASK), (COUNT))
#define MP_ROR_64(MASK, COUNT) _rotr64((MASK), (COUNT))
#ifdef MP_DEBUG
#define MP_INLINE_ALWAYS
#define MP_INLINE_NEVER
#else
#define MP_INLINE_ALWAYS __forceinline
#define MP_INLINE_NEVER __declspec(noinline)
#endif
#define MP_ASSUME(EXPRESSION) __assume((EXPRESSION))
#else
#error "MPMALLOC: UNSUPPORTED COMPILER"
#endif

#ifdef MP_DEBUG
#include <assert.h>
#include <stdlib.h>
#define MP_INVARIANT(EXPRESSION) assert(EXPRESSION)
#define MP_UNREACHABLE abort()
#else
#define MP_INVARIANT(EXPRESSION) MP_ASSUME((EXPRESSION))
#define MP_UNREACHABLE MP_ASSUME(MP_FALSE)
#endif
#define MP_FLOOR_LOG2_32(VALUE) (uint8_t)(31 - MP_CLZ_32(VALUE))
#define MP_FLOOR_LOG2_64(VALUE) (uint8_t)(63 - MP_CLZ_64(VALUE))
#define MP_CEIL_LOG2_32(VALUE) (uint8_t)(32 - MP_CLZ_32((VALUE) - 1))
#define MP_CEIL_LOG2_64(VALUE) (uint8_t)(64 - MP_CLZ_64((VALUE) - 1))
#define MP_CEIL_POW2_32(VALUE) (1U << (32 - MP_CLZ_32((VALUE) - 1U)))
#define MP_CEIL_POW2_64(VALUE) (1ULL << (64 - MP_CLZ_64((VALUE) - 1ULL)))
#ifdef MP_32BIT
#define MP_POPCOUNT(MASK) MP_POPCOUNT_32((MASK))
#define MP_CTZ(MASK) MP_CTZ_32((MASK))
#define MP_CLZ(MASK) MP_CLZ_32((MASK))
#define MP_FLOOR_LOG2(VALUE) MP_FLOOR_LOG2_32(VALUE)
#define MP_CEIL_LOG2(VALUE) MP_CEIL_LOG2_32(VALUE)
#define MP_CEIL_POW2(VALUE) MP_CEIL_POW2_32(VALUE)
#else
#define MP_POPCOUNT(MASK) MP_POPCOUNT_64((MASK))
#define MP_CTZ(MASK) MP_CTZ_64((MASK))
#define MP_CLZ(MASK) MP_CLZ_64((MASK))
#define MP_FLOOR_LOG2(VALUE) MP_FLOOR_LOG2_64(VALUE)
#define MP_CEIL_LOG2(VALUE) MP_CEIL_LOG2_64(VALUE)
#define MP_CEIL_POW2(VALUE) MP_CEIL_POW2_64(VALUE)
#endif
#define MP_BT(MASK, INDEX) ((MASK) & ((size_t)1 << (INDEX)))
#define MP_BS(MASK, INDEX) ((MASK) |= ((size_t)1 << (INDEX)))
#define MP_BR(MASK, INDEX) ((MASK) &= ~((size_t)1 << (INDEX)))
#define MP_ARRAY_SIZE(ARRAY) (sizeof(ARRAY) / sizeof(ARRAY[0]))
#define MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY (MP_CACHE_LINE_SIZE * 8)
#define MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT (MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY / (8 * MP_PTR_SIZE))
#define MP_BLOCK_ALLOCATOR_MAX_CAPACITY (MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY / 2)
#define MP_BLOCK_ALLOCATOR_MASK_COUNT (MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT / 2)
#define MP_SHARED_ATTR MP_ALIGNAS(MP_CACHE_LINE_SIZE)
#ifdef MP_DEBUG
static_assert((MP_REDZONE_SIZE & ((UINTMAX_C(1) << MP_PTR_SIZE_LOG2) - UINTMAX_C(1))) == 0, "Error, MP_REDZONE_SIZE must be a multiple of sizeof(size_t).");
#endif

// ================================================================
//	ATOMIC INTRINSICS
// ================================================================

#ifdef MP_CLANG_OR_GCC
#define MP_ATOMIC(TYPE) TYPE volatile
typedef MP_ATOMIC(mp_bool) mp_atomic_bool;
#define MP_ATOMIC_TEST_ACQ(WHERE) __atomic_load_n((const mp_atomic_bool*)(WHERE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_TAS_ACQ(WHERE) __atomic_test_and_set((mp_atomic_bool*)(WHERE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_CLEAR_REL(WHERE) __atomic_clear((mp_atomic_bool*)(WHERE), __ATOMIC_RELEASE)
#define MP_ATOMIC_LOAD_ACQ_UPTR(WHERE) __atomic_load_n((const mp_atomic_size_t*)(WHERE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_STORE_REL_UPTR(WHERE, VALUE) __atomic_store_n((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_XCHG_ACQ_UPTR(WHERE, VALUE) __atomic_exchange_n((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_CMPXCHG_ACQ_UPTR(WHERE, EXPECTED, VALUE) __atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_ATOMIC_CMPXCHG_REL_UPTR(WHERE, EXPECTED, VALUE) __atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_FALSE, __ATOMIC_RELEASE, __ATOMIC_RELAXED)
#define MP_ATOMIC_CMPXCHG_WEAK_ACQ_UPTR(WHERE, EXPECTED, VALUE)	__atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_TRUE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_ATOMIC_CMPXCHG_WEAK_REL_UPTR(WHERE, EXPECTED, VALUE)	__atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_TRUE, __ATOMIC_RELEASE, __ATOMIC_RELAXED)
#define MP_ATOMIC_FAA_ACQ(WHERE, VALUE) __atomic_fetch_add((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_FAA_REL(WHERE, VALUE) __atomic_fetch_add((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_FAS_ACQ(WHERE, VALUE) __atomic_fetch_sub((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_FAS_REL(WHERE, VALUE) __atomic_fetch_sub((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_BIT_SET_REL(WHERE, VALUE) (void)__atomic_fetch_or((mp_atomic_size_t*)(WHERE), (size_t)1 << (uint_fast8_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_ACQUIRE_FENCE __atomic_thread_fence(__ATOMIC_ACQUIRE)
#ifdef MP_32BIT
#define MP_ATOMIC_WCMPXCHG_ACQ(WHERE, EXPECTED, VALUE) __atomic_compare_exchange_n((volatile int64_t*)(WHERE), (int64_t*)(EXPECTED), *(const int64_t*)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_ATOMIC_WCMPXCHG_REL(WHERE, EXPECTED, VALUE) __atomic_compare_exchange_n((volatile int64_t*)(WHERE), (int64_t*)(EXPECTED), *(const int64_t*)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#else
#define MP_ATOMIC_WCMPXCHG_ACQ(WHERE, EXPECTED, VALUE) __atomic_compare_exchange_n((volatile __int128*)(WHERE), (__int128*)(EXPECTED), *(const __int128*)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_ATOMIC_WCMPXCHG_REL(WHERE, EXPECTED, VALUE) __atomic_compare_exchange_n((volatile __int128*)(WHERE), (__int128*)(EXPECTED), *(const __int128*)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#endif
#define MP_ATOMIC_WLOAD_ACQ(WHERE, TARGET) (void)memcpy(&(TARGET), (const void*)(WHERE), MP_DPTR_SIZE); __atomic_thread_fence(__ATOMIC_ACQUIRE)
#elif defined(MP_MSVC)
#ifndef MP_STRING_JOIN
#define MP_STRING_JOIN(LHS, RHS) LHS##RHS
#endif
// I'd like to give special thanks to the visual studio dev team for being more than 10 years ahead of the competition in not adding support to the C11 standard to their compiler.
#define MP_ATOMIC(TYPE) TYPE volatile
typedef MP_ATOMIC(CHAR) mp_atomic_bool;
typedef CHAR mp_msvc_bool;
typedef volatile CHAR mp_msvc_atomic_bool;
#ifdef _M_ARM
#define MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(NAME) MP_STRING_JOIN(NAME, _acq)
#define MP_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(NAME) MP_STRING_JOIN(NAME, _rel)
#else
#define MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(NAME) NAME
#define MP_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(NAME) NAME
#endif
#ifdef MP_32BIT
typedef LONG mp_msvc_size_t;
#define MP_MSVC_ATOMIC_ACQ(NAME) MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(NAME)
#define MP_MSVC_ATOMIC_REL(NAME) MP_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(NAME)
#else
typedef LONG64 mp_msvc_size_t;
#define MP_MSVC_ATOMIC_ACQ(NAME) MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(MP_STRING_JOIN(NAME, 64))
#define MP_MSVC_ATOMIC_REL(NAME) MP_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(MP_STRING_JOIN(NAME, 64))
#endif
typedef volatile mp_msvc_size_t mp_msvc_atomic_size_t;
#define MP_ATOMIC_TEST_ACQ(WHERE) (mp_bool)MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(_InterlockedOr8)((mp_msvc_atomic_bool*)(WHERE), (mp_msvc_bool)0)
#define MP_ATOMIC_TAS_ACQ(WHERE) (mp_bool)MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(_InterlockedExchange8)((mp_msvc_atomic_bool*)(WHERE), (mp_msvc_bool)1)
#define MP_ATOMIC_CLEAR_REL(WHERE) (void)MP_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(_InterlockedExchange8)((mp_msvc_atomic_bool*)(WHERE), (mp_msvc_bool)0)
#define MP_ATOMIC_LOAD_ACQ_UPTR(WHERE) MP_MSVC_ATOMIC_ACQ(_InterlockedOr)((mp_msvc_atomic_size_t*)(WHERE), 0)
#define MP_ATOMIC_STORE_REL_UPTR(WHERE, VALUE) (void)MP_MSVC_ATOMIC_REL(_InterlockedExchange)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_XCHG_ACQ_UPTR(WHERE, VALUE) MP_MSVC_ATOMIC_ACQ(_InterlockedExchange)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_CMPXCHG_ACQ_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_ACQ(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE), *(const mp_msvc_size_t*)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_CMPXCHG_REL_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_REL(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE), *(const mp_msvc_size_t*)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_CMPXCHG_WEAK_ACQ_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_ACQ(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE), *(const mp_msvc_size_t*)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_CMPXCHG_WEAK_REL_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_REL(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE), *(const mp_msvc_size_t*)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_FAA_ACQ(WHERE, VALUE) (size_t)MP_MSVC_ATOMIC_ACQ(_InterlockedExchangeAdd)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_FAA_REL(WHERE, VALUE) (size_t)MP_MSVC_ATOMIC_REL(_InterlockedExchangeAdd)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_FAS_ACQ(WHERE, VALUE) (size_t)MP_MSVC_ATOMIC_ACQ(_InterlockedExchangeAdd)((mp_msvc_atomic_size_t*)(WHERE), -(mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_FAS_REL(WHERE, VALUE) (size_t)MP_MSVC_ATOMIC_REL(_InterlockedExchangeAdd)((mp_msvc_atomic_size_t*)(WHERE), -(mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_BIT_SET_REL(WHERE, VALUE) (void)MP_MSVC_ATOMIC_REL(_interlockedbittestandset)((mp_msvc_atomic_size_t*)(WHERE), (uint_fast8_t)(VALUE))
#define MP_ATOMIC_ACQUIRE_FENCE _ReadBarrier()

typedef struct mp_msvc_uintptr_pair { MP_ALIGNAS(MP_DPTR_SIZE) size_t a; size_t b; } mp_msvc_uintptr_pair;

MP_INLINE_ALWAYS static mp_bool mp_impl_cmpxchg16_acq(volatile mp_msvc_uintptr_pair* where, mp_msvc_uintptr_pair* expected, const mp_msvc_uintptr_pair* desired)
{
	MP_INVARIANT(MP_IS_ALIGNED(where, MP_DPTR_SIZE));
#ifdef MP_32BIT
	return MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(_InterlockedCompareExchange64)((volatile LONG64*)where, *(const LONG64*)desired, *(const LONG64*)expected) == *(const LONG64*)expected;
#else
	return (mp_bool)MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(_InterlockedCompareExchange128)((volatile LONG64*)where, desired->b, desired->a, (LONG64*)expected);
#endif
}

MP_INLINE_ALWAYS static mp_bool mp_impl_cmpxchg16_rel(volatile mp_msvc_uintptr_pair* where, mp_msvc_uintptr_pair* expected, const mp_msvc_uintptr_pair* desired)
{
	MP_INVARIANT(MP_IS_ALIGNED(where, MP_DPTR_SIZE));
#ifdef MP_32BIT
	return MP_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(_InterlockedCompareExchange64)((volatile LONG64*)where, *(const LONG64*)desired, *(const LONG64*)expected) == *(const LONG64*)expected;
#else
	return (mp_bool)MP_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(_InterlockedCompareExchange128)((volatile LONG64*)where, desired->b, desired->a, (LONG64*)expected);
#endif
}

#define MP_ATOMIC_WLOAD_ACQ(WHERE, TARGET)				MP_INVARIANT(MP_IS_ALIGNED((WHERE), MP_DPTR_SIZE)); (void)memcpy((void*)&(TARGET), (const void*)(WHERE), MP_DPTR_SIZE); MP_ATOMIC_ACQUIRE_FENCE
#define MP_ATOMIC_WCMPXCHG_ACQ(WHERE, EXPECTED, VALUE)	mp_impl_cmpxchg16_acq((volatile mp_msvc_uintptr_pair*)(WHERE), (mp_msvc_uintptr_pair*)(EXPECTED), (const mp_msvc_uintptr_pair*)(VALUE))
#define MP_ATOMIC_WCMPXCHG_REL(WHERE, EXPECTED, VALUE)	mp_impl_cmpxchg16_rel((volatile mp_msvc_uintptr_pair*)(WHERE), (mp_msvc_uintptr_pair*)(EXPECTED), (const mp_msvc_uintptr_pair*)(VALUE))
#endif
#define MP_ATOMIC_LOAD_ACQ_PTR(WHERE) (void*)MP_ATOMIC_LOAD_ACQ_UPTR((mp_atomic_size_t*)WHERE)
#define MP_ATOMIC_STORE_REL_PTR(WHERE, VALUE) MP_ATOMIC_STORE_REL_UPTR((mp_atomic_size_t*)WHERE, (size_t)VALUE)
#define MP_ATOMIC_XCHG_ACQ_PTR(WHERE, VALUE) (void*)MP_ATOMIC_XCHG_ACQ_UPTR((mp_atomic_size_t*)WHERE, (size_t)VALUE)
#define MP_ATOMIC_CMPXCHG_ACQ_PTR(WHERE, EXPECTED, VALUE) MP_ATOMIC_CMPXCHG_ACQ_UPTR((mp_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)
#define MP_ATOMIC_CMPXCHG_REL_PTR(WHERE, EXPECTED, VALUE) MP_ATOMIC_CMPXCHG_REL_UPTR((mp_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)
#define MP_ATOMIC_CMPXCHG_WEAK_ACQ_PTR(WHERE, EXPECTED, VALUE) MP_ATOMIC_CMPXCHG_WEAK_ACQ_UPTR((mp_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)
#define MP_ATOMIC_CMPXCHG_WEAK_REL_PTR(WHERE, EXPECTED, VALUE) MP_ATOMIC_CMPXCHG_WEAK_REL_UPTR((mp_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)
#define MP_NON_ATOMIC_SET(WHERE) (*((mp_bool*)&(WHERE)) = MP_TRUE)
#define MP_NON_ATOMIC_LOAD_PTR(WHERE) *((const void**)(WHERE))
#define MP_NON_ATOMIC_STORE_PTR(WHERE, VALUE) *((void**)(WHERE)) = (VALUE)
#define MP_NON_ATOMIC_LOAD_UPTR(WHERE) *((const size_t*)(WHERE))
#define MP_NON_ATOMIC_STORE_UPTR(WHERE, VALUE) *((size_t*)(WHERE)) = (VALUE)
#define MP_PTRS_PER_ZMMWORD (64 / MP_PTR_SIZE)
#define MP_PTRS_PER_YMMWORD (32 / MP_PTR_SIZE)
#define MP_PTRS_PER_XMMWORD (16 / MP_PTR_SIZE)
#define MP_PTRS_PER_QWORD (8 / MP_PTR_SIZE)
#define MP_PTRS_PER_DWORD (4 / MP_PTR_SIZE)

#ifdef MP_DEBUG
#define MP_JUNKPTR_CHECK(PTR) MP_INVARIANT(memcmp(&(PTR), &junkptr, MP_PTR_SIZE) != 0)
#else
#define MP_JUNKPTR_CHECK(PTR)
#endif

// ================================================================
//	MISCELLANEOUS
// ================================================================

#define MP_ZERO_COLD_16(PTR) _mm_stream_si128((__m128i*)(PTR), _mm_setzero_si128())
#define MP_ZERO_COLD_32(PTR) _mm256_stream_si256((__m256i*)(PTR), _mm256_setzero_si256())
#define MP_ZERO_COLD_64(PTR) _mm512_stream_si512((__m512i*)(PTR), _mm512_setzero_si512())

MP_INLINE_ALWAYS static void mp_zero_fill_block_allocator_marked_map(void* ptr)
{
	uint8_t* i = (uint8_t*)ptr;
#if (MP_CACHE_LINE_SIZE / 2) == 64
#ifdef MP_HAS_AVX512F
	MP_ZERO_COLD_64(i);
#elif defined(MP_HAS_AVX)
	MP_ZERO_COLD_32(i); MP_ZERO_COLD_32(i + 32);
#elif defined(MP_HAS_SSE2)
	MP_ZERO_COLD_32(i); MP_ZERO_COLD_32(i + 16);
	MP_ZERO_COLD_32(i + 32); MP_ZERO_COLD_32(i + 48);
#else
	(void)memset(ptr, 0, MP_CACHE_LINE_SIZE / 2);
#endif
#elif (MP_CACHE_LINE_SIZE / 2) == 32
#ifdef MP_HAS_AVX
	MP_ZERO_COLD_32(i);
#elif defined(MP_HAS_SSE2)
	MP_ZERO_COLD_32(i);
	MP_ZERO_COLD_32(i + 16);
#else
	(void)memset(ptr, 0, MP_CACHE_LINE_SIZE / 2);
#endif
#elif (MP_CACHE_LINE_SIZE / 2) == 16
#ifdef MP_HAS_SSE2
	MP_ZERO_COLD_32(i);
#else
	(void)memset(ptr, 0, MP_CACHE_LINE_SIZE / 2);
#endif
#endif
}

MP_INLINE_ALWAYS static void mp_zero_fill_block_allocator_intrusive_marked_map(void* ptr)
{
	uint8_t* i = (uint8_t*)ptr;
#if MP_CACHE_LINE_SIZE == 128
#ifdef MP_HAS_AVX512F
	MP_ZERO_COLD_64(i);
	MP_ZERO_COLD_64(i + 64);
#elif defined(MP_HAS_AVX)
	MP_ZERO_COLD_32(i); MP_ZERO_COLD_32(i + 32);
	MP_ZERO_COLD_32(i + 64); MP_ZERO_COLD_32(i + 96);
#elif defined(MP_HAS_SSE2)
	MP_ZERO_COLD_32(i); MP_ZERO_COLD_32(i + 16); MP_ZERO_COLD_32(i + 32); MP_ZERO_COLD_32(i + 48);
	MP_ZERO_COLD_32(i + 64); MP_ZERO_COLD_32(i + 80); MP_ZERO_COLD_32(i + 96); MP_ZERO_COLD_32(i + 112);
#else
	(void)memset(ptr, 0, MP_CACHE_LINE_SIZE);
#endif
#elif MP_CACHE_LINE_SIZE == 64
#ifdef MP_HAS_AVX512F
	MP_ZERO_COLD_64(i);
#elif defined(MP_HAS_AVX)
	MP_ZERO_COLD_32(i);
	MP_ZERO_COLD_32(i + 32);
#elif defined(MP_HAS_SSE2)
	MP_ZERO_COLD_32(i); MP_ZERO_COLD_32(i + 16);
	MP_ZERO_COLD_32(i + 32); MP_ZERO_COLD_32(i + 48);
#else
	(void)memset(ptr, 0, MP_CACHE_LINE_SIZE);
#endif
#elif MP_CACHE_LINE_SIZE == 32
#ifdef MP_HAS_AVX
	MP_ZERO_COLD_32(i);
#elif defined(MP_HAS_SSE2)
	MP_ZERO_COLD_32(i);
	MP_ZERO_COLD_32(i + 16);
#else
	(void)memset(ptr, 0, MP_CACHE_LINE_SIZE);
#endif
#endif
}

MP_INLINE_ALWAYS static uint_fast8_t fast_prng(uint32_t* state)
{
	*state *= 3;
	*state = MP_ROR_32(*state, 13);
	return (uint8_t)(*state >> 1);
}

// ================================================================
//	MPMALLOC MAIN DATA TYPES
// ================================================================

typedef MP_ATOMIC(size_t) mp_atomic_size_t;

typedef struct mp_flist_node { struct mp_flist_node* next; } mp_flist_node;

typedef struct mp_wcas_list_head
{
	MP_ALIGNAS(MP_DPTR_SIZE) mp_flist_node* head;
	size_t counter;
} mp_wcas_list_head;

typedef MP_ATOMIC(mp_wcas_list_head) mp_wcas_list;
MP_STATIC_ASSERT(sizeof(mp_wcas_list_head) == MP_DPTR_SIZE, "");

#ifndef MP_STRICT_CHUNK_FREELIST
typedef size_t mp_chunk_list_head;
#else
typedef mp_wcas_list_head mp_chunk_list_head;
#endif

typedef MP_ATOMIC(mp_chunk_list_head) mp_chunk_list;

typedef struct mp_persistent_node
{
	MP_SHARED_ATTR struct mp_persistent_node* next;
	mp_atomic_size_t bump;
} mp_persistent_node;
typedef MP_ATOMIC(mp_persistent_node*) mp_persistent_allocator;

typedef struct mp_block_allocator
{
	MP_SHARED_ATTR struct mp_block_allocator* next;
	struct mp_tcache* owner;
	uint8_t* buffer;
	uint32_t free_count;
	uint16_t flags;
	uint8_t size_class;
	mp_atomic_bool linked;
	size_t free_map[MP_BLOCK_ALLOCATOR_MASK_COUNT];
#ifdef MP_LEGACY_COMPATIBLE
	size_t allocator_map[MP_BLOCK_ALLOCATOR_MASK_COUNT];
#endif
	MP_SHARED_ATTR mp_atomic_size_t marked_map[MP_BLOCK_ALLOCATOR_MASK_COUNT];
} mp_block_allocator;

typedef struct mp_block_allocator_intrusive
{
	MP_SHARED_ATTR struct mp_block_allocator_intrusive* next;
	struct mp_tcache* owner;
	uint32_t free_count;
	uint16_t flags;
	uint8_t size_class;
	mp_atomic_bool linked;
	MP_SHARED_ATTR size_t free_map[MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT];
#ifdef MP_LEGACY_COMPATIBLE
	MP_SHARED_ATTR size_t allocator_map[MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT];
#endif
	MP_SHARED_ATTR mp_atomic_size_t marked_map[MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT];
} mp_block_allocator_intrusive;

typedef struct mp_tcache_stats
{
	size_t malloc_count;
	size_t free_count;
	size_t active_memory;
	size_t total_memory;
	size_t peak_memory;
} mp_tcache_stats;

typedef struct mp_tcache
{
	MP_SHARED_ATTR mp_block_allocator_intrusive** bins;
	mp_block_allocator** bins_large;
	mp_wcas_list* recovered_small;
	mp_wcas_list* recovered_large;
	struct mp_tcache* next;
	mp_tcache_stats stats;
	mp_atomic_bool is_active;
} mp_tcache;

static MP_TLS mp_tcache* this_tcache;

typedef struct mp_tcache_pool_head
{
	MP_ALIGNAS(MP_DPTR_SIZE) mp_tcache* head;
	size_t generation;
} mp_tcache_pool_head;
MP_STATIC_ASSERT(sizeof(mp_tcache_pool_head) == MP_DPTR_SIZE, "");

typedef struct mp_shared_counter { MP_SHARED_ATTR mp_atomic_size_t value; } mp_shared_counter;

// ================================================================
//	PLATFORM INFO
// ================================================================

static void* min_address;
static void* max_address;
static size_t page_size;
static size_t chunk_size;
static size_t chunk_size_mask;
static size_t large_page_size;
static uint8_t page_size_log2;
static uint8_t chunk_size_log2;
static uint8_t tcache_small_sc_count;
static uint8_t tcache_large_sc_count;
#ifdef MP_64BIT
static mp_bool mp_init_flag;
#endif
#ifdef MP_DEBUG
static void* junkptr;
static mp_debug_options debugger;
static mp_bool mp_debug_enabled_flag;
#endif

// ================================================================
//	SIZE CLASS MAPPING FUNCTIONS
// ================================================================

#define MP_SIZE_MAP_MAX_FLOOR_LOG2 11
#define MP_SIZE_MAP_MAX_CEIL_LOG2 (MP_SIZE_MAP_MAX_FLOOR_LOG2 + 1)
#define MP_SIZE_CLASS_COUNT 60

static const uint8_t MP_SIZE_MAP_ALIGNMENT_LOG2S[MP_SIZE_MAP_MAX_CEIL_LOG2]	= { 0, 0, 0, 0, 2, 3, 3, 4, 5, 6, 7, 8 };
static const uint8_t MP_SIZE_MAP_SUBCLASS_COUNTS[MP_SIZE_MAP_MAX_CEIL_LOG2]	= { 1, 1, 1, 1, 4, 4, 8, 8, 8, 8, 8, 8 };
static const uint8_t MP_SIZE_MAP_OFFSETS[MP_SIZE_MAP_MAX_CEIL_LOG2 + 1]		= { 0, 1, 2, 3, 4, 8, 12, 20, 28, 36, 44, 52, 60 };

#if MP_CACHE_LINE_SIZE == 32
#define MP_MAX_BLOCK_ALLOCATOR_INTRUSIVE_MULTIBLOCK_HEADER 15
#elif MP_CACHE_LINE_SIZE == 64
#define MP_MAX_BLOCK_ALLOCATOR_INTRUSIVE_MULTIBLOCK_HEADER 21
#elif MP_CACHE_LINE_SIZE == 128
#define MP_MAX_BLOCK_ALLOCATOR_INTRUSIVE_MULTIBLOCK_HEADER 31
#else
#error ""
#endif

MP_ULTRAPURE MP_INLINE_ALWAYS static uint_fast8_t mp_size_to_sc(size_t size)
{
	uint_fast8_t i, j;
	uint_fast32_t tmp, step;
	MP_UNLIKELY_IF(size == 0)
		return 0;
	i = MP_FLOOR_LOG2(size);
	MP_UNLIKELY_IF(i > 11)
		return MP_SIZE_CLASS_COUNT + MP_CEIL_LOG2(size) - page_size_log2;
	tmp = 1U << i;
	step = 1U << MP_SIZE_MAP_ALIGNMENT_LOG2S[i];
	for (j = 0; j != MP_SIZE_MAP_SUBCLASS_COUNTS[i]; ++j)
	{
		MP_UNLIKELY_IF(tmp >= size)
			return MP_SIZE_MAP_OFFSETS[i] + j;
		tmp += step;
	}
	return MP_SIZE_MAP_OFFSETS[i + 1];
}

MP_ULTRAPURE MP_INLINE_ALWAYS static uint_fast8_t mp_sc_large_bin_index(uint_fast8_t sc)
{
	MP_INVARIANT(sc >= MP_SIZE_CLASS_COUNT);
	return sc - (MP_SIZE_CLASS_COUNT + 1);
}

MP_ULTRAPURE MP_INLINE_ALWAYS static uint_fast8_t mp_sc_to_size_large_log2(uint_fast8_t sc)
{
	MP_INVARIANT(sc >= MP_SIZE_CLASS_COUNT);
	return mp_sc_large_bin_index(sc) + page_size_log2 + 1;
}

MP_ULTRAPURE MP_INLINE_ALWAYS static uint_fast32_t mp_sc_to_size_small(uint_fast8_t sc)
{
	uint_fast32_t r;
	uint_fast8_t a, b;
	mp_bool flag;
	if (sc <= 4)
		return 1U << sc;
	flag = sc < 12;
	sc -= MP_SELECT_U8(flag, 4, 12);
	a = MP_SELECT_U8(flag, 4 + (sc >> 2), 6 + (sc >> 3));
	b = sc & MP_SELECT_U8(flag, 3, 7);
	r = (1U << a) + (1U << MP_SIZE_MAP_ALIGNMENT_LOG2S[a]) * b;
	return r;
}

MP_ULTRAPURE MP_INLINE_ALWAYS static size_t mp_sc_to_size(uint_fast8_t sc)
{
	MP_LIKELY_IF(sc < MP_SIZE_CLASS_COUNT)
		return mp_sc_to_size_small(sc);
	return (size_t)1 << mp_sc_to_size_large_log2(sc);
}

// ================================================================
//	DEBUG FUNCTIONS
// ================================================================

#ifdef MP_DEBUG
#include <stdio.h>
static void mp_default_debug_message_callback(void* context, const char* message, size_t size)
{
	(void)fwrite(message, 1, size, stdout);
}

static void mp_default_debug_warning_callback(void* context, const char* message, size_t size)
{
	(void)fwrite(message, 1, size, stdout);
}

static void mp_default_debug_error_callback(void* context, const char* message, size_t size)
{
	(void)fwrite(message, 1, size, stderr);
}
#endif

MP_INLINE_ALWAYS static void mp_init_redzone(void* buffer, size_t size)
{
#ifdef MP_CHECK_OVERFLOW
	MP_UNLIKELY_IF(buffer != NULL)
		(void)memset((uint8_t*)buffer + size, MP_REDZONE_VALUE, MP_REDZONE_SIZE);
#endif
}

// ================================================================
//	OS / BACKEND FUNCTIONS
// ================================================================

#ifdef MP_TARGET_WINDOWS
typedef PVOID(WINAPI* VirtualAlloc2_t)(HANDLE Process, PVOID BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG PageProtection, MEM_EXTENDED_PARAMETER* ExtendedParameters, ULONG ParameterCount);

static VirtualAlloc2_t va2_ptr;
static ULONG va2_flags;
static MEM_ADDRESS_REQUIREMENTS va2_addr_req;
static MEM_EXTENDED_PARAMETER va2_ext_param;

#if defined(MP_LARGE_PAGE_SUPPORT) || defined(MP_PAGE_MESHING_SUPPORT)
MP_INLINE_ALWAYS static mp_bool mp_win32_acquire_lock_memory_privilege()
{
	DWORD n;
	HANDLE h;
	TOKEN_USER users[64];
	LSA_HANDLE policy;
	LSA_OBJECT_ATTRIBUTES attrs;
	LSA_UNICODE_STRING rights;
	TOKEN_PRIVILEGES p;
	h = NULL;
	MP_UNLIKELY_IF(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h))
		return MP_FALSE;
	n = sizeof(users);
	MP_UNLIKELY_IF(!GetTokenInformation(h, TokenUser, users, n, &n))
		return MP_FALSE;
	(void)CloseHandle(h);
	(void)memset(&attrs, 0, sizeof(attrs));
	MP_UNLIKELY_IF(!LsaOpenPolicy(NULL, &attrs, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &policy))
		return MP_FALSE;
	rights.Buffer = (PWSTR)SE_LOCK_MEMORY_NAME;
	rights.Length = (USHORT)(wcslen(rights.Buffer) * sizeof(WCHAR));
	rights.MaximumLength = rights.Length + (USHORT)sizeof(WCHAR);
	MP_UNLIKELY_IF(!LsaAddAccountRights(policy, users->User.Sid, &rights, 1))
		return MP_FALSE;
	h = NULL;
	MP_UNLIKELY_IF(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h))
		return MP_FALSE;
	p.PrivilegeCount = 1;
	p.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	MP_UNLIKELY_IF(!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &p.Privileges[0].Luid))
		return MP_FALSE;
	MP_UNLIKELY_IF(!AdjustTokenPrivileges(h, FALSE, &p, 0, NULL, 0))
		return MP_FALSE;
	(void)CloseHandle(h);
	return MP_TRUE;
}
#endif

MP_INLINE_ALWAYS static mp_bool mp_os_init(const mp_init_options* options)
{
	HMODULE m;
	m = GetModuleHandle(TEXT("KernelBase.DLL"));
	MP_UNLIKELY_IF(m == NULL)
		return MP_FALSE;
	va2_ptr = (VirtualAlloc2_t)GetProcAddress(m, "VirtualAlloc2");
	MP_UNLIKELY_IF(va2_ptr == NULL)
		return MP_FALSE;
	va2_addr_req.Alignment = chunk_size;
	va2_addr_req.HighestEndingAddress = max_address;
	va2_addr_req.LowestStartingAddress = min_address;
	va2_ext_param.Type = MemExtendedParameterAddressRequirements;
	va2_ext_param.Pointer = &va2_addr_req;
	va2_flags = MEM_RESERVE | MEM_COMMIT;
#if defined(MP_LARGE_PAGE_SUPPORT) || defined(MP_PAGE_MESHING_SUPPORT)
	MP_LIKELY_IF((options->flags & (MP_INIT_ENABLE_LARGE_PAGES | MP_INIT_ENABLE_PAGE_MESHING)) != 0)
		MP_UNLIKELY_IF(!mp_win32_acquire_lock_memory_privilege())
			return MP_FALSE;
	MP_LIKELY_IF(options->flags & MP_INIT_ENABLE_LARGE_PAGES)
		va2_flags |= MEM_LARGE_PAGES;
#else
	MP_INVARIANT(!(options->flags & MP_INIT_ENABLE_LARGE_PAGES));
#endif
	return MP_TRUE;
}

MP_INLINE_ALWAYS static void* mp_os_malloc(size_t size)
{
	return va2_ptr(GetCurrentProcess(), NULL, size, va2_flags, PAGE_READWRITE, &va2_ext_param, 1);
}

MP_INLINE_ALWAYS static mp_bool mp_os_resize(void* ptr, size_t old_size, size_t new_size) { return MP_FALSE; }

MP_INLINE_ALWAYS static void mp_os_free(void* ptr, size_t size)
{
	mp_bool result;
	MP_INVARIANT(ptr != NULL);
	result = (mp_bool)VirtualFree(ptr, 0, MEM_RELEASE);
	MP_INVARIANT(result);
}

MP_INLINE_ALWAYS static void mp_os_purge(void* ptr, size_t size)
{
	MP_INVARIANT(ptr != NULL);
	(void)DiscardVirtualMemory(ptr, size);
}

#elif defined(MP_TARGET_LINUX)

static int mmap_protection;
static int mmap_flags;

MP_INLINE_ALWAYS static void mp_os_init(mp_bool enable_large_pages)
{
	mmap_protection = PROT_READ | PROT_WRITE;
	mmap_flags = MAP_ANON | MAP_UNINITIALIZED;
	if (enable_large_pages)
		mmap_flags |= MAP_HUGETLB;
}

MP_INLINE_ALWAYS static void* mp_os_malloc(size_t size)
{
	uint8_t* tmp = mmap(NULL, size * 2, mmap_protection, mmap_flags, -1, 0);
	uint8_t* tmp_limit = base + chunk_size * 2;
	uint8_t* r = (uint8_t*)MP_ALIGN_FLOOR_MASK((size_t)tmp, chunk_size_mask);
	uint8_t* r_limit = base + chunk_size;
	MP_LIKELY_IF(tmp != r)
		(void)munmap(tmp, r - tmp);
	MP_LIKELY_IF(tmp_limit != r_limit)
		(void)munmap(base_limit, tmp_limit - r_limit);
	return base;
}

MP_INLINE_ALWAYS static void mp_os_free(void* ptr, size_t size)
{
	MP_INVARIANT(ptr != NULL);
	(void)munmap(ptr, size);
}

MP_INLINE_ALWAYS static void mp_os_purge(void* ptr, size_t size)
{
	MP_INVARIANT(ptr != NULL);
	(void)madvise(ptr, size, MADV_DONTNEED);
}

#endif

#ifndef MP_NO_CUSTOM_BACKEND
static void mp_empty_function() { }
static mp_fn_init backend_init = mp_os_init;
static mp_fn_cleanup backend_cleanup = mp_empty_function;
static mp_fn_malloc backend_malloc = mp_os_malloc;
static mp_fn_resize backend_resize = mp_os_resize;
static mp_fn_free backend_free = mp_os_free;
static mp_fn_purge backend_purge = mp_os_purge;
#endif

// ================================================================
//	CMPXCHG16B-BASED LOCK-FREE FREE-LIST
// ================================================================

MP_INLINE_ALWAYS static void mp_wcas_list_push(mp_wcas_list* head, void* ptr)
{
	MP_JUNKPTR_CHECK(ptr);
	mp_flist_node* new_head;
	mp_wcas_list_head prior, desired;
	new_head = (mp_flist_node*)ptr;
	desired.head = new_head;
	MP_SPIN_LOOP
	{
		MP_ATOMIC_WLOAD_ACQ(head, prior);
		MP_JUNKPTR_CHECK(prior.head);
		new_head->next = prior.head;
		desired.counter = prior.counter + 1;
		MP_LIKELY_IF(MP_ATOMIC_WCMPXCHG_ACQ(head, &prior, &desired))
			break;
	}
}

MP_INLINE_ALWAYS static void* mp_wcas_list_peek(mp_wcas_list* head)
{
	mp_wcas_list_head prior;
	MP_ATOMIC_WLOAD_ACQ(head, prior);
	return prior.head;
}

MP_INLINE_ALWAYS static void* mp_wcas_list_pop(mp_wcas_list* head)
{
	mp_flist_node* r;
	mp_wcas_list_head prior, desired;
	MP_SPIN_LOOP
	{
		MP_ATOMIC_WLOAD_ACQ(head, prior);
		r = prior.head;
		MP_UNLIKELY_IF(r == NULL)
			return NULL;
		MP_JUNKPTR_CHECK(r);
#ifdef MP_64BIT
		MP_PREFETCH(r);
#endif
		desired.head = r->next;
		desired.counter = prior.counter + 1;
		MP_LIKELY_IF(MP_ATOMIC_WCMPXCHG_REL(head, &prior, &desired))
			return r;
	}
}

MP_INLINE_NEVER static void* mp_wcas_list_pop_all(mp_wcas_list* head)
{
	mp_flist_node* r;
	mp_wcas_list_head prior, desired;
	MP_SPIN_LOOP
	{
		MP_ATOMIC_WLOAD_ACQ(head, prior);
		r = prior.head;
		MP_UNLIKELY_IF(r == NULL)
			return NULL;
		MP_JUNKPTR_CHECK(r);
		MP_PREFETCH(prior.head);
		desired.head = NULL;
		desired.counter = prior.counter + 1;
		MP_LIKELY_IF(MP_ATOMIC_WCMPXCHG_REL(head, &prior, &desired))
			return r;
	}
}

// ================================================================
//	LOCK-FREE CHUNK FREE LIST
// ================================================================

MP_INLINE_ALWAYS static void mp_chunk_list_push(mp_chunk_list* head, void* ptr)
{
	MP_JUNKPTR_CHECK(ptr);
#ifndef MP_STRICT_CHUNK_FREELIST
	mp_flist_node* new_head;
	mp_chunk_list_head prior, desired;
	new_head = (mp_flist_node*)ptr;
	MP_SPIN_LOOP
	{
		prior = MP_ATOMIC_LOAD_ACQ_UPTR(head);
		new_head->next = (mp_flist_node*)(prior & ~chunk_size_mask);
		MP_JUNKPTR_CHECK(new_head->next);
		desired = (size_t)new_head | (((prior & chunk_size_mask) + 1) & chunk_size_mask);
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_WEAK_REL_UPTR(head, &prior, desired))
			break;
	}
#else
	mp_wcas_list_push(head, ptr);
#endif
}

MP_INLINE_ALWAYS static void* mp_chunk_list_pop(mp_chunk_list* head)
{
#ifndef MP_STRICT_CHUNK_FREELIST
	mp_flist_node* r;
	mp_chunk_list_head prior, desired;
	MP_SPIN_LOOP
	{
		prior = MP_ATOMIC_LOAD_ACQ_UPTR(head);
		r = (mp_flist_node*)(prior & ~chunk_size_mask);
		MP_UNLIKELY_IF(r == NULL)
			return NULL;
		MP_JUNKPTR_CHECK(r);
		desired = (size_t)r->next | (((prior & chunk_size_mask) + 1) & chunk_size_mask);
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_WEAK_ACQ_UPTR(head, &prior, desired))
			return r;
	}
#else
	return mp_wcas_list_push(head);
#endif
}

// ================================================================
//	PERSISTENT
// ================================================================

MP_INLINE_ALWAYS static void* mp_persistent_node_malloc(mp_persistent_node* allocator, size_t size)
{
	size_t prior;
	prior = MP_ATOMIC_LOAD_ACQ_UPTR(&allocator->bump);
	MP_UNLIKELY_IF(prior + size > chunk_size)
		return NULL;
	prior = MP_ATOMIC_FAA_ACQ(&allocator->bump, size);
	MP_LIKELY_IF(prior + size <= chunk_size)
		return (uint8_t*)allocator + prior;
	(void)MP_ATOMIC_FAS_REL(&allocator->bump, size);
	return NULL;
}

static mp_persistent_allocator internal_persistent_allocator;
static mp_persistent_allocator public_persistent_allocator;

MP_ATTR void* MP_CALL mp_persistent_malloc_impl(mp_persistent_allocator* allocator, size_t size)
{
	void* r;
	mp_persistent_node* n;
	mp_persistent_node* prior;
	mp_persistent_node* current;
	size_t offset;
	size = MP_ALIGN_CEIL(size, MP_CACHE_LINE_SIZE);
	MP_UNLIKELY_IF(size >= chunk_size)
		return mp_lcache_malloc(MP_ALIGN_CEIL_MASK(size, chunk_size_mask), 0);
	current = (mp_persistent_node*)MP_ATOMIC_LOAD_ACQ_PTR(allocator);
	do
	{
		prior = current;
		for (n = prior; n != NULL; n = n->next)
		{
			r = mp_persistent_node_malloc(n, size);
			MP_LIKELY_IF(r != NULL)
				return r;
		}
		current = (mp_persistent_node*)MP_ATOMIC_LOAD_ACQ_PTR(allocator);
	} while (prior != current);
	n = (mp_persistent_node*)mp_lcache_malloc(chunk_size, 0);
	MP_UNLIKELY_IF(n == NULL)
		return NULL;
	offset = MP_ALIGN_CEIL(sizeof(mp_persistent_node), MP_CACHE_LINE_SIZE);
	r = (uint8_t*)n + offset;
	offset += size;
	n->bump = offset;
	MP_SPIN_LOOP
	{
		prior = (mp_persistent_node*)MP_ATOMIC_LOAD_ACQ_PTR(allocator);
		n->next = prior;
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_WEAK_ACQ_PTR(allocator, &prior, n))
			return r;
	}
}

MP_ATTR void MP_CALL mp_persistent_cleanup_impl(mp_persistent_allocator* allocator)
{
	mp_persistent_node* next;
	mp_persistent_node* n;
	for (n = (mp_persistent_node*)MP_ATOMIC_XCHG_ACQ_PTR(allocator, NULL); n != NULL; n = next)
	{
		next = n->next;
		mp_backend_free(n, chunk_size);
	}
}

// ================================================================
//	THREAD CACHE POOL
// ================================================================

MP_SHARED_ATTR static MP_ATOMIC(mp_tcache_pool_head) tcache_freelist;

MP_INLINE_ALWAYS static mp_tcache* mp_tcache_acquire_fast()
{
	mp_tcache_pool_head prior, desired;
	MP_SPIN_LOOP
	{
		(void)memcpy(&prior, (const void*)&tcache_freelist, MP_DPTR_SIZE);
		MP_ATOMIC_ACQUIRE_FENCE;
		MP_UNLIKELY_IF(prior.head == NULL)
			return NULL;
		MP_JUNKPTR_CHECK(prior.head);
		MP_PREFETCH(prior.head);
		desired.head = prior.head->next;
		desired.generation = prior.generation + 1;
		MP_LIKELY_IF(MP_ATOMIC_WCMPXCHG_ACQ(&tcache_freelist, &prior, &desired))
			break;
	}
	return prior.head;
}

MP_INLINE_NEVER static mp_tcache* mp_tcache_acquire_slow()
{
	mp_tcache* r;
	uint8_t* buffer;
	size_t buffer_size;
	buffer_size = sizeof(mp_tcache);
	buffer_size += (size_t)tcache_small_sc_count << MP_PTR_SIZE_LOG2;
	buffer_size += (size_t)tcache_large_sc_count << MP_PTR_SIZE_LOG2;
	buffer_size = MP_ALIGN_CEIL(buffer_size, MP_CACHE_LINE_SIZE);
	buffer_size += (size_t)tcache_small_sc_count * sizeof(mp_wcas_list);
	buffer_size += (size_t)tcache_large_sc_count * sizeof(mp_wcas_list);
	buffer_size = MP_ALIGN_CEIL(buffer_size, MP_CACHE_LINE_SIZE);
	buffer = (uint8_t*)mp_persistent_malloc_impl(&internal_persistent_allocator, buffer_size);
	MP_INVARIANT(buffer != NULL);
#if defined(MP_DEBUG) || !defined(MP_NO_CUSTOM_BACKEND)
	(void)memset(buffer, 0, buffer_size);
#endif
	r = (mp_tcache*)buffer;
	buffer += sizeof(mp_tcache);
	r->bins = (mp_block_allocator_intrusive**)buffer;
	buffer = (uint8_t*)(r->bins + tcache_small_sc_count);
	r->bins_large = (mp_block_allocator**)buffer;
	buffer = (uint8_t*)MP_ALIGN_CEIL((size_t)(r->bins_large + tcache_large_sc_count), MP_DPTR_SIZE);
	r->recovered_small = (mp_wcas_list*)buffer;
	MP_INVARIANT(MP_IS_ALIGNED(r->recovered_small, MP_DPTR_SIZE));
	buffer = (uint8_t*)(r->recovered_small + tcache_small_sc_count);
	r->recovered_large = (mp_wcas_list*)buffer;
	MP_INVARIANT(MP_IS_ALIGNED(r->recovered_large, MP_DPTR_SIZE));
	return r;
}

MP_INLINE_ALWAYS static mp_tcache* mp_tcache_acquire()
{
	mp_tcache* r;
	r = mp_tcache_acquire_fast();
	MP_UNLIKELY_IF(r == NULL)
		r = mp_tcache_acquire_slow();
	return r;
}

MP_INLINE_ALWAYS static void mp_tcache_release(mp_tcache* tcache)
{
	mp_tcache_pool_head prior, desired;
	desired.head = tcache;
	MP_SPIN_LOOP
	{
		(void)memcpy(&prior, (const void*)&tcache_freelist, MP_DPTR_SIZE);
		MP_ATOMIC_ACQUIRE_FENCE;
		tcache->next = prior.head;
		desired.generation = prior.generation + 1;
		MP_LIKELY_IF(MP_ATOMIC_WCMPXCHG_REL(&tcache_freelist, &prior, &desired))
			break;
	}
}

// ================================================================
//	SHARED RECOVERY CACHE
// ================================================================

static mp_wcas_list* rcache_small;
static mp_wcas_list* rcache_large;

MP_INLINE_ALWAYS static void mp_rcache_init()
{
	size_t buffer_size;
	uint8_t* buffer;
	buffer_size = ((size_t)tcache_large_sc_count + tcache_small_sc_count) * sizeof(mp_wcas_list);
	buffer = (uint8_t*)mp_persistent_malloc(buffer_size);
	(void)memset(buffer, 0, buffer_size);
	rcache_small = (mp_wcas_list*)buffer;
	buffer = (uint8_t*)(rcache_small + tcache_small_sc_count);
	rcache_large = (mp_wcas_list*)buffer;
}

// ================================================================
//	BLOCK ALLOCATOR
// ================================================================

MP_INLINE_ALWAYS static void mp_block_allocator_init(mp_block_allocator* allocator, uint_fast8_t sc, struct mp_tcache* owner, void* buffer)
{
	uint_fast8_t block_size_log2;
	uint_fast32_t mask_count, bit_count;
	block_size_log2 = mp_sc_to_size_large_log2(sc);
	mp_zero_fill_block_allocator_marked_map((void*)allocator->marked_map);
	MP_INVARIANT(allocator != NULL);
	MP_INVARIANT(buffer != NULL);
	allocator->next = NULL;
	allocator->free_count = 1U << (chunk_size_log2 - block_size_log2);
	allocator->flags = 0;
	allocator->size_class = sc;
	allocator->owner = owner;
	allocator->buffer = (uint8_t*)buffer;
	MP_NON_ATOMIC_SET(allocator->linked);
	(void)memset(allocator->free_map, 0, MP_CACHE_LINE_SIZE / 2);
	mask_count = allocator->free_count >> MP_PTR_BITS_LOG2;
	bit_count = allocator->free_count & MP_PTR_BITS_MASK;
	(void)memset(allocator->free_map, 0xff, (size_t)mask_count << MP_PTR_SIZE_LOG2);
	allocator->free_map[mask_count] |= ((size_t)1 << bit_count) - (size_t)1;
}

MP_ULTRAPURE MP_INLINE_ALWAYS static uint_fast8_t mp_block_allocator_intrusive_reserved_count_of(uint_fast8_t sc)
{
	size_t k;
	k = mp_sc_to_size_small(sc);
	return sc < MP_MAX_BLOCK_ALLOCATOR_INTRUSIVE_MULTIBLOCK_HEADER ? (uint8_t)((sizeof(mp_block_allocator_intrusive) + (k - 1)) / k) : 1;
}

MP_INLINE_ALWAYS static void mp_block_allocator_intrusive_init(mp_block_allocator_intrusive* allocator, uint_fast8_t sc, struct mp_tcache* owner)
{
	uint_fast32_t mask_count, bit_count, reserved_count;
	MP_INVARIANT(allocator != NULL);
	mp_zero_fill_block_allocator_intrusive_marked_map((void*)allocator->marked_map);
	MP_INVARIANT(sc < tcache_small_sc_count);
	reserved_count = mp_block_allocator_intrusive_reserved_count_of(sc);
	MP_INVARIANT(reserved_count >= 1);
	allocator->next = NULL;
	allocator->free_count = MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY - reserved_count;
	MP_INVARIANT(reserved_count < allocator->free_count);
	allocator->flags = 0;
	allocator->size_class = sc;
	allocator->owner = owner;
	MP_NON_ATOMIC_SET(allocator->linked);
	(void)memset(allocator->free_map, 0xff, MP_CACHE_LINE_SIZE);
	mask_count = reserved_count >> MP_PTR_BITS_LOG2;
	bit_count = reserved_count & MP_PTR_BITS_MASK;
	(void)memset(allocator->free_map, 0, (size_t)mask_count << MP_PTR_SIZE_LOG2);
	allocator->free_map[mask_count] &= ~(((size_t)1 << bit_count) - (size_t)1);
}

MP_ULTRAPURE MP_INLINE_ALWAYS static size_t mp_chunk_size_of(size_t size)
{
	MP_INVARIANT(size != 0);
	MP_UNLIKELY_IF(size <= page_size)
		return MP_CEIL_POW2(size * MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY);
	size *= MP_BLOCK_ALLOCATOR_MAX_CAPACITY;
	MP_UNLIKELY_IF(size >= chunk_size)
		return chunk_size;
	return MP_CEIL_POW2(size);
}

MP_PURE MP_INLINE_ALWAYS static mp_bool mp_is_valid_block_allocator(mp_block_allocator* allocator)
{
	return
		allocator->owner != NULL && allocator->buffer != NULL &&
		allocator->free_count <= MP_BLOCK_ALLOCATOR_MAX_CAPACITY &&
		mp_sc_to_size(allocator->size_class) > page_size && mp_sc_to_size_large_log2(allocator->size_class) < chunk_size_log2 &&
		(uint8_t)allocator->linked < 2;
}

MP_PURE MP_INLINE_ALWAYS static mp_bool mp_is_valid_block_allocator_intrusive(mp_block_allocator_intrusive* allocator)
{
	return
		allocator->owner != NULL && allocator->free_count < MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY &&
		mp_sc_to_size(allocator->size_class) != 0 && allocator->size_class < tcache_small_sc_count &&
		(uint8_t)allocator->linked < 2;
}

MP_PURE MP_INLINE_ALWAYS static uint_fast32_t mp_block_allocator_index_of(mp_block_allocator* allocator, void* ptr)
{
	MP_INVARIANT(mp_is_valid_block_allocator(allocator));
	return (uint_fast32_t)(((size_t)((uint8_t*)ptr - (uint8_t*)allocator->buffer)) >> mp_sc_to_size_large_log2(allocator->size_class));
}

MP_PURE MP_INLINE_ALWAYS static uint_fast32_t mp_block_allocator_intrusive_index_of(mp_block_allocator_intrusive* allocator, void* ptr)
{
	MP_INVARIANT(mp_is_valid_block_allocator_intrusive(allocator));
	return (uint_fast32_t)(((size_t)((uint8_t*)ptr - (uint8_t*)allocator)) / mp_sc_to_size(allocator->size_class));
}

MP_PURE MP_INLINE_ALWAYS static mp_bool mp_block_allocator_owns(mp_block_allocator* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_is_valid_block_allocator(allocator));
	MP_UNLIKELY_IF((uint8_t*)ptr < (uint8_t*)allocator->buffer)
		return MP_FALSE;
	MP_UNLIKELY_IF((uint8_t*)ptr >= (uint8_t*)allocator->buffer + chunk_size)
		return MP_FALSE;
	index = mp_block_allocator_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_BITS_LOG2;
	bit_index = index & MP_PTR_BITS_MASK;
	return !MP_BT(allocator->free_map[mask_index], bit_index);
}

MP_PURE MP_INLINE_ALWAYS static mp_bool mp_block_allocator_intrusive_owns(mp_block_allocator_intrusive* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_is_valid_block_allocator_intrusive(allocator));
	MP_UNLIKELY_IF((uint8_t*)ptr < (uint8_t*)allocator)
		return MP_FALSE;
	MP_UNLIKELY_IF((uint8_t*)ptr >= (uint8_t*)allocator + mp_chunk_size_of(mp_sc_to_size(allocator->size_class)))
		return MP_FALSE;
	index = mp_block_allocator_intrusive_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_BITS_LOG2;
	bit_index = index & MP_PTR_BITS_MASK;
	return !MP_BT(allocator->free_map[mask_index], bit_index);
}

MP_INLINE_ALWAYS static uint_fast32_t mp_block_allocator_reclaim_inline(size_t* free_map, mp_atomic_size_t* marked_map, uint_fast32_t bitmask_count)
{
	size_t mask;
	uint_fast32_t i, freed_count;
	for (freed_count = i = 0; i != bitmask_count; ++i)
	{
		MP_UNLIKELY_IF(MP_ATOMIC_LOAD_ACQ_UPTR(marked_map + i) == 0)
			continue;
		mask = MP_ATOMIC_XCHG_ACQ_UPTR(marked_map + i, 0);
		freed_count += MP_POPCOUNT(mask);
		free_map[i] |= mask;
	}
	return freed_count;
}

MP_INLINE_NEVER static uint_fast32_t mp_block_allocator_reclaim_noinline(size_t* free_map, mp_atomic_size_t* marked_map, uint_fast32_t bitmask_count)
{
	return mp_block_allocator_reclaim_inline(free_map, marked_map, bitmask_count);
}

MP_INLINE_ALWAYS static void* mp_block_allocator_malloc(mp_block_allocator* allocator)
{
	void* r;
	uint_fast32_t mask_index, bit_index;
#ifdef MP_DEBUG
	assert(allocator->linked != 0);
#endif
	MP_INVARIANT(allocator->free_count != 0);
	for (mask_index = 0; mask_index != MP_BLOCK_ALLOCATOR_MASK_COUNT; ++mask_index)
		MP_UNLIKELY_IF(allocator->free_map[mask_index] != 0)
			break;
	MP_INVARIANT(mask_index != MP_BLOCK_ALLOCATOR_MASK_COUNT);
	bit_index = MP_CTZ(allocator->free_map[mask_index]);
	MP_INVARIANT(MP_BT(allocator->free_map[mask_index], bit_index));
	MP_BR(allocator->free_map[mask_index], bit_index);
	--allocator->free_count;
	MP_UNLIKELY_IF(allocator->free_count == 0)
		allocator->free_count += mp_block_allocator_reclaim_noinline(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_MASK_COUNT);
	r = allocator->buffer + ((((size_t)mask_index << MP_PTR_BITS_LOG2) | bit_index) << mp_sc_to_size_large_log2(allocator->size_class));
	MP_INVARIANT(r < allocator->buffer + ((size_t)MP_BLOCK_ALLOCATOR_MAX_CAPACITY << mp_sc_to_size_large_log2(allocator->size_class)));
	return r;
}

MP_INLINE_ALWAYS static void* mp_block_allocator_intrusive_malloc(mp_block_allocator_intrusive* allocator)
{
	void* r;
	uint_fast32_t mask_index, bit_index;
#ifdef MP_DEBUG
	assert(allocator->linked != 0);
#endif
	MP_INVARIANT(allocator->free_count != 0);
	for (mask_index = 0; mask_index != MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT; ++mask_index)
		MP_UNLIKELY_IF(allocator->free_map[mask_index] != 0)
			break;
	MP_INVARIANT(mask_index != MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT);
	bit_index = MP_CTZ(allocator->free_map[mask_index]);
	MP_INVARIANT(((mask_index << MP_PTR_BITS_LOG2) | bit_index) >= mp_block_allocator_intrusive_reserved_count_of(allocator->size_class));
	MP_BR(allocator->free_map[mask_index], bit_index);
	--allocator->free_count;
	MP_UNLIKELY_IF(allocator->free_count == 0)
		allocator->free_count += mp_block_allocator_reclaim_noinline(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT);
	r = (uint8_t*)allocator + ((((size_t)mask_index << MP_PTR_BITS_LOG2) | bit_index) * mp_sc_to_size(allocator->size_class));
	MP_INVARIANT(
		r >= (uint8_t*)allocator + mp_block_allocator_intrusive_reserved_count_of(allocator->size_class) * mp_sc_to_size(allocator->size_class) &&
		r < (uint8_t*)allocator + (MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY * mp_sc_to_size(allocator->size_class)));
	return r;
}

typedef void (*mp_fn_block_allocator_recover)(void* bin, void* allocator, mp_atomic_bool* linked);

MP_INLINE_NEVER static void mp_block_allocator_recover(mp_flist_node** bin, mp_block_allocator* allocator)
{
	mp_flist_node* desired;
	// At this point only the current thread can access this block allocator's free_map, so we can do this:
	MP_UNLIKELY_IF(allocator->free_count == 0)
		allocator->free_count += mp_block_allocator_reclaim_inline(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_MASK_COUNT);
	MP_INVARIANT(allocator->free_count != 0);
	MP_UNLIKELY_IF(allocator->free_count == MP_BLOCK_ALLOCATOR_MAX_CAPACITY)
		return mp_lcache_free(allocator, chunk_size);
	MP_UNLIKELY_IF(!*(const mp_bool*)&allocator->owner->is_active)
		mp_wcas_list_push(rcache_large + mp_sc_large_bin_index(allocator->size_class), allocator);
	desired = (mp_flist_node*)allocator;
	desired->next = *bin;
	*bin = desired;
}

MP_INLINE_NEVER static void mp_block_allocator_intrusive_recover(mp_flist_node** bin, mp_block_allocator_intrusive* allocator)
{
	mp_flist_node* desired;
	MP_UNLIKELY_IF(allocator->free_count == 0)
		allocator->free_count += mp_block_allocator_reclaim_inline(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_MASK_COUNT);
	MP_INVARIANT(allocator->free_count != 0);
	MP_UNLIKELY_IF(allocator->free_count == MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY - mp_block_allocator_intrusive_reserved_count_of(allocator->size_class))
		return mp_free_sized(allocator, mp_chunk_size_of(mp_sc_to_size(allocator->size_class)));
	MP_UNLIKELY_IF(!*(const mp_bool*)&allocator->owner->is_active)
		mp_wcas_list_push(rcache_small + allocator->size_class, allocator);
	desired = (mp_flist_node*)allocator;
	desired->next = *bin;
	*bin = desired;
}

MP_INLINE_NEVER static void mp_block_allocator_recover_shared(mp_wcas_list* recovered_small, mp_block_allocator* allocator)
{
	MP_UNLIKELY_IF(allocator->free_count == 0)
		allocator->free_count += mp_block_allocator_reclaim_inline(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_MASK_COUNT);
	MP_INVARIANT(allocator->free_count != 0);
	MP_UNLIKELY_IF(allocator->free_count == MP_BLOCK_ALLOCATOR_MAX_CAPACITY)
		return mp_lcache_free(allocator, chunk_size);
	MP_UNLIKELY_IF(!MP_ATOMIC_TEST_ACQ(allocator->owner->is_active))
		recovered_small = rcache_large + mp_sc_large_bin_index(allocator->size_class);
	mp_wcas_list_push(recovered_small, allocator);
}

MP_INLINE_NEVER static void mp_block_allocator_intrusive_recover_shared(mp_wcas_list* recovered_small, mp_block_allocator_intrusive* allocator)
{
	MP_UNLIKELY_IF(allocator->free_count == 0)
		allocator->free_count += mp_block_allocator_reclaim_inline(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT);
	MP_INVARIANT(allocator->free_count != 0);
	MP_UNLIKELY_IF(allocator->free_count == MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY - mp_block_allocator_intrusive_reserved_count_of(allocator->size_class))
		return mp_free_sized(allocator, mp_chunk_size_of(mp_sc_to_size(allocator->size_class)));
	MP_UNLIKELY_IF(!MP_ATOMIC_TEST_ACQ(allocator->owner->is_active))
		recovered_small = rcache_small + allocator->size_class;
	mp_wcas_list_push(recovered_small, allocator);
}

MP_INLINE_ALWAYS static void mp_block_allocator_intrusive_free(mp_block_allocator_intrusive* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_block_allocator_intrusive_owns(allocator, ptr));
	++allocator->free_count;
	index = mp_block_allocator_intrusive_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_BITS_LOG2;
	bit_index = index & MP_PTR_BITS_MASK;
	MP_BS(allocator->free_map[mask_index], bit_index);
	MP_UNLIKELY_IF(!MP_ATOMIC_TEST_ACQ(&allocator->linked) && MP_ATOMIC_TAS_ACQ(&allocator->linked))
		mp_block_allocator_intrusive_recover((mp_flist_node**)(allocator->owner->bins + allocator->size_class), allocator);
}

MP_INLINE_ALWAYS static void mp_block_allocator_intrusive_free_shared(mp_block_allocator_intrusive* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_block_allocator_intrusive_owns(allocator, ptr));
	index = mp_block_allocator_intrusive_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_BITS_LOG2;
	bit_index = index & MP_PTR_BITS_MASK;
	MP_ATOMIC_BIT_SET_REL(allocator->marked_map + mask_index, bit_index);
	MP_UNLIKELY_IF(!MP_ATOMIC_TEST_ACQ(&allocator->linked) && MP_ATOMIC_TAS_ACQ(&allocator->linked))
		mp_block_allocator_intrusive_recover_shared(allocator->owner->recovered_small + allocator->size_class, allocator);
}

MP_INLINE_ALWAYS static void mp_block_allocator_free(mp_block_allocator* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_block_allocator_owns(allocator, ptr));
	++allocator->free_count;
	index = mp_block_allocator_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_BITS_LOG2;
	bit_index = index & MP_PTR_BITS_MASK;
	MP_BS(allocator->free_map[mask_index], bit_index);
	MP_UNLIKELY_IF(!MP_ATOMIC_TEST_ACQ(&allocator->linked) && MP_ATOMIC_TAS_ACQ(&allocator->linked))
		mp_block_allocator_recover((mp_flist_node**)(allocator->owner->bins_large + mp_sc_large_bin_index(allocator->size_class)), allocator);
}

MP_INLINE_ALWAYS static void mp_block_allocator_free_shared(mp_block_allocator* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_block_allocator_owns(allocator, ptr));
	index = mp_block_allocator_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_BITS_LOG2;
	bit_index = index & MP_PTR_BITS_MASK;
	MP_ATOMIC_BIT_SET_REL(allocator->marked_map + mask_index, bit_index);
	MP_UNLIKELY_IF(!MP_ATOMIC_TEST_ACQ(&allocator->linked) && MP_ATOMIC_TAS_ACQ(&allocator->linked))
		mp_block_allocator_recover_shared(allocator->owner->recovered_large + mp_sc_large_bin_index(allocator->size_class), allocator);
}

// ================================================================
//	64-BIT CHUNK DIGITAL TREE
// ================================================================

#ifdef MP_64BIT
typedef uint8_t* mp_trie_leaf;
typedef MP_ATOMIC(mp_trie_leaf)* mp_trie_branch;
typedef MP_ATOMIC(mp_trie_branch) mp_trie_root;

static size_t branch_size;
static size_t branch_mask;
static size_t leaf_size;
static size_t leaf_mask;
static uint8_t leaf_log2;
static uint8_t branch_log2;

typedef struct mp_trie
{
	mp_trie_root roots[256];
} mp_trie;

static void* mp_trie_find(mp_trie* trie, size_t key, uint_fast8_t value_size_log2)
{
	uint_fast8_t root_index;
	size_t branch_index, leaf_index, offset;
	mp_trie_branch branch;
	mp_trie_leaf leaf;
	leaf_index = key & leaf_mask;
	key >>= leaf_log2;
	branch_index = key & branch_mask;
	key >>= branch_log2;
	root_index = (uint_fast8_t)key;
	branch = (mp_trie_branch)MP_ATOMIC_LOAD_ACQ_PTR(trie->roots + root_index);
	MP_UNLIKELY_IF(branch == NULL)
		return NULL;
	branch += branch_index;
	leaf = (mp_trie_leaf)MP_ATOMIC_LOAD_ACQ_PTR(branch);
	MP_UNLIKELY_IF(leaf == NULL)
		return NULL;
	offset = leaf_index << value_size_log2;
	MP_INVARIANT(offset + (1ULL << value_size_log2) <= (leaf_size << value_size_log2));
	return leaf + offset;
}

static void* mp_trie_insert(mp_trie* trie, size_t key, uint_fast8_t value_size_log2)
{
	uint_fast8_t root_index;
	size_t branch_index, leaf_index, offset, real_branch_size, real_leaf_size;
	mp_trie_branch branch, new_branch;
	mp_trie_leaf leaf, new_leaf;
	real_branch_size = branch_size << MP_PTR_SIZE_LOG2;
	real_leaf_size = leaf_size << value_size_log2;
	leaf_index = key & leaf_mask;
	key >>= leaf_log2;
	branch_index = key & branch_mask;
	key >>= branch_log2;
	root_index = (uint_fast8_t)key;
	branch = (mp_trie_branch)MP_ATOMIC_LOAD_ACQ_PTR(trie->roots + root_index);
	MP_LIKELY_IF(branch == NULL)
	{
		new_branch = (mp_trie_branch)mp_lcache_malloc(real_branch_size, 0);
		MP_UNLIKELY_IF(new_branch == NULL)
			return NULL;
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_REL_PTR(trie->roots + root_index, &branch, new_branch))
		{
			branch = new_branch;
			(void)memset((size_t*)branch, 0, real_branch_size);
		}
		else
		{
			mp_lcache_free((void*)new_branch, real_branch_size);
		}
	}
	MP_INVARIANT(branch != NULL);
	branch += branch_index;
	leaf = (mp_trie_leaf)MP_ATOMIC_LOAD_ACQ_PTR(branch);
	MP_LIKELY_IF(leaf == NULL)
	{
		new_leaf = (mp_trie_leaf)mp_lcache_malloc(real_leaf_size, 0);
		MP_UNLIKELY_IF(new_leaf == NULL)
			return NULL;
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_REL_PTR(branch, &leaf, new_leaf))
			leaf = new_leaf;
		else
			mp_lcache_free(new_leaf, real_leaf_size);
	}
	offset = leaf_index << value_size_log2;
	MP_INVARIANT(offset + (1ULL << value_size_log2) <= real_leaf_size);
	leaf += offset;
	return leaf;
}

#ifndef MP_DISABLE_CHUNK_TRIE_SHORTCUT
typedef struct mp_trie_shortcut_ctrl
{
	MP_ALIGNAS(8) uint8_t count;
	uint8_t hints[7];
} mp_trie_shortcut_ctrl;

typedef struct mp_trie_shortcut
{
	MP_ATOMIC(mp_trie_shortcut_ctrl) ctrl;
	MP_ATOMIC(size_t) keys;
} mp_trie_shortcut;

MP_INLINE_ALWAYS static uint_fast16_t mp_trie_shortcut_hash(size_t key)
{
	uint32_t mask;
	mask = (uint32_t)key ^ (uint32_t)(key >> 16);
	return (uint16_t)mask ^ (uint16_t)(mask >> 16);
}

MP_INLINE_ALWAYS static size_t mp_trie_shortcut_find(mp_trie_shortcut* shortcut, size_t key, uint_fast8_t value_size_log2)
{
	mp_trie_shortcut_ctrl ctrl;
	uint64_t prior, current;
	uint_fast16_t hash;
	uint_fast8_t i, hint;
	hash = mp_trie_shortcut_hash(key);
	hint = (uint8_t)hash;
	hash >>= 8;
	shortcut += hash;
	current = MP_ATOMIC_LOAD_ACQ_UPTR(&shortcut->ctrl);
	do
	{
		prior = current;
		(void)memcpy(&ctrl, &prior, 8);
		for (i = 0; i != ctrl.count; ++i)
			MP_LIKELY_IF(ctrl.hints[i] == hint && MP_ATOMIC_LOAD_ACQ_UPTR(shortcut->keys + i) == key)
				return (size_t)hash * 7 + i;
		current = MP_ATOMIC_LOAD_ACQ_UPTR(&shortcut->ctrl);
	} while (prior == current);
	return UINTPTR_MAX;
}

MP_INLINE_ALWAYS static size_t mp_trie_shortcut_insert(mp_trie_shortcut* shortcut, size_t key, uint_fast8_t value_size_log2)
{
	mp_trie_shortcut_ctrl ctrl;
	uint64_t prior, desired;
	uint_fast16_t hash;
	uint_fast8_t hint;
	hash = mp_trie_shortcut_hash(key);
	hint = (uint8_t)hash;
	hash >>= 8;
	shortcut += hash;
	MP_SPIN_LOOP
	{
		prior = MP_ATOMIC_LOAD_ACQ_UPTR(&shortcut->ctrl);
		(void)memcpy(&ctrl, &prior, 8);
		MP_INVARIANT(ctrl.count < 7);
		MP_UNLIKELY_IF(ctrl.count == 7)
			return UINTPTR_MAX;
		ctrl.hints[ctrl.count] = hint;
		++ctrl.count;
		(void)memcpy(&desired, &ctrl, 8);
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_ACQ_UPTR(&shortcut->ctrl, &prior, desired))
			break;
	}
	--ctrl.count;
	MP_ATOMIC_STORE_REL_UPTR(&shortcut->keys + ctrl.count, key);
	return (size_t)hash * 7 + ctrl.count;
}

MP_INLINE_ALWAYS static size_t mp_trie_shortcut_erase(mp_trie_shortcut* shortcut, size_t key, uint_fast8_t value_size_log2)
{
	mp_trie_shortcut_ctrl ctrl;
	uint64_t prior, desired;
	uint_fast16_t hash;
	uint_fast8_t i, hint;
	hash = mp_trie_shortcut_hash(key);
	hint = (uint8_t)hash;
	hash >>= 8;
	shortcut += hash;
	MP_SPIN_LOOP
	{
		prior = MP_ATOMIC_LOAD_ACQ_UPTR(&shortcut->ctrl);
		(void)memcpy(&ctrl, &prior, 8);
		MP_INVARIANT(ctrl.count < 7);
		for (i = 0; i != ctrl.count; ++i)
			MP_LIKELY_IF(ctrl.hints[i] == hint && MP_ATOMIC_LOAD_ACQ_UPTR(shortcut->keys + i) == key)
				break;
		MP_UNLIKELY_IF(i == ctrl.count)
			return UINTPTR_MAX;
		MP_INVARIANT(ctrl.count != 0);
		--ctrl.count;
		MP_LIKELY_IF(ctrl.count != 0)
			ctrl.hints[i] = ctrl.hints[ctrl.count];
		(void)memcpy(&desired, &ctrl, 8);
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_REL_UPTR(&shortcut->ctrl, &prior, desired))
			break;
	}
	(void)MP_ATOMIC_CMPXCHG_REL_UPTR(&shortcut->keys + i, &key, 0);
	return (size_t)hash * 7 + ctrl.count - 1;
}
#endif
#endif

// ================================================================
//	LARGE CACHE
// ================================================================

#ifdef MP_32BIT
#ifdef MP_DEBUG
static size_t lcache_bin_count;
#endif
static mp_chunk_list* lcache_bins;
#else
static mp_trie lcache_bins;
MP_SHARED_ATTR static MP_ATOMIC(mp_chunk_list) single_chunk_list;
#endif
MP_SHARED_ATTR static MP_ATOMIC(size_t) lcache_total_memory;
MP_SHARED_ATTR static MP_ATOMIC(size_t) lcache_active_memory;
MP_SHARED_ATTR static MP_ATOMIC(size_t) lcache_peak_memory;

MP_INLINE_ALWAYS static void mp_lcache_init()
{
#ifdef MP_32BIT
#ifndef MP_DEBUG
	size_t lcache_bin_count;
#endif
	size_t k;
	lcache_bin_count = 1 << (32 - chunk_size_log2);
	k = lcache_bin_count * sizeof(mp_chunk_list);
	lcache_bins = (mp_chunk_list*)mp_persistent_malloc_impl(&internal_persistent_allocator, k);
	MP_INVARIANT(lcache_bins != NULL);
#if defined(MP_DEBUG) || !defined(MP_NO_CUSTOM_BACKEND)
	(void)memset((size_t*)lcache_bins, 0, k);
#endif
#else
	uint_fast8_t n;
	n = 64 - chunk_size_log2;
	leaf_log2 = chunk_size_log2 - 4;
	branch_log2 = n - chunk_size_log2 - 4;
	branch_size = 1ULL << branch_log2;
	leaf_size = 1ULL << leaf_log2;
	branch_mask = branch_size - 1;
	leaf_mask = leaf_size - 1;
	MP_INVARIANT(leaf_log2 + branch_log2 + 8 == (64 - chunk_size_log2));
#endif
}

MP_INLINE_ALWAYS static mp_chunk_list* mp_lcache_find_bin(size_t size)
{
	size >>= chunk_size_log2;
#ifdef MP_32BIT
	size -= size != 0;
	return lcache_bins + size;
#else
	MP_LIKELY_IF(size <= chunk_size)
		return &single_chunk_list;
	--size;
	return (mp_chunk_list*)mp_trie_find(&lcache_bins, size, MP_CEIL_LOG2(sizeof(mp_chunk_list)));
#endif
}

MP_INLINE_ALWAYS static mp_chunk_list* mp_lcache_insert_bin(size_t size)
{
#ifdef MP_32BIT
	return mp_lcache_find_bin(size);
#else
	size >>= chunk_size_log2;
	MP_LIKELY_IF(size <= chunk_size)
		return &single_chunk_list;
	--size;
	return (mp_chunk_list*)mp_trie_insert(&lcache_bins, size, MP_CEIL_LOG2(sizeof(mp_chunk_list)));
#endif
}

// ================================================================
//	THREAD CACHE
// ================================================================

#ifdef MP_32BIT
static mp_block_allocator* tcache_lookup;
#else
static mp_trie tcache_lookup;
#endif

MP_INLINE_ALWAYS static void mp_this_tcache_check_integrity()
{
#ifdef MP_DEBUG
	mp_block_allocator_intrusive* allocator_intrusive;
	mp_block_allocator* allocator;
	size_t i;
	for (i = 0; i != tcache_small_sc_count; ++i)
		for (allocator_intrusive = this_tcache->bins[i]; allocator_intrusive != NULL; allocator_intrusive = allocator_intrusive->next)
			MP_INVARIANT(mp_is_valid_block_allocator_intrusive(allocator_intrusive));
	for (i = 0; i != tcache_large_sc_count; ++i)
		for (allocator = this_tcache->bins_large[i]; allocator != NULL; allocator = allocator->next)
			MP_INVARIANT(mp_is_valid_block_allocator(allocator));
	for (i = 0; i != tcache_small_sc_count; ++i)
		for (allocator_intrusive = (mp_block_allocator_intrusive*)mp_wcas_list_peek(this_tcache->recovered_small + i); allocator_intrusive != NULL; allocator_intrusive = allocator_intrusive->next)
			MP_INVARIANT(mp_is_valid_block_allocator_intrusive(allocator_intrusive));
	for (i = 0; i != tcache_large_sc_count; ++i)
		for (allocator = (mp_block_allocator*)mp_wcas_list_peek(this_tcache->recovered_large + i); allocator != NULL; allocator = allocator->next)
			MP_INVARIANT(mp_is_valid_block_allocator(allocator));
#endif
}

#ifdef MP_32BIT
MP_INLINE_ALWAYS static void mp_tcache_lookup_init()
{
	size_t k = (1U << (32 - chunk_size_log2)) * sizeof(mp_block_allocator);
	tcache_lookup = (mp_block_allocator*)mp_persistent_malloc_impl(&internal_persistent_allocator, k);
	MP_DEBUG_JUNK_FILL(tcache_lookup, k);
}
#endif

MP_INLINE_ALWAYS static mp_block_allocator* mp_tcache_find_allocator(const void* ptr)
{
	size_t id;
	id = (size_t)ptr >> chunk_size_log2;
#ifdef MP_32BIT
	MP_INVARIANT(tcache_lookup != NULL);
	return tcache_lookup + id;
#else
	return (mp_block_allocator*)mp_trie_find(&tcache_lookup, id, MP_CEIL_LOG2(sizeof(mp_block_allocator)));
#endif
}

MP_INLINE_ALWAYS static mp_block_allocator* mp_tcache_insert_allocator(const void* ptr)
{
#ifdef MP_32BIT
	return mp_tcache_find_allocator(ptr);
#else
	size_t id;
	id = (size_t)ptr >> chunk_size_log2;
	return (mp_block_allocator*)mp_trie_insert(&tcache_lookup, id, MP_CEIL_LOG2(sizeof(mp_block_allocator)));
#endif
}

static void* mp_tcache_malloc_small_slow(mp_tcache* tcache, size_t size, uint_fast8_t sc)
{
	void* r;
	size_t k;
	mp_block_allocator_intrusive* allocator;
	mp_block_allocator_intrusive** bin;
	bin = tcache->bins + sc;
	MP_INVARIANT(this_tcache != NULL);
	k = mp_chunk_size_of(size);
	allocator = (mp_block_allocator_intrusive*)mp_malloc(k);
	MP_UNLIKELY_IF(allocator == NULL)
		return NULL;
	mp_block_allocator_intrusive_init(allocator, sc, this_tcache);
	r = mp_block_allocator_intrusive_malloc(allocator);
	allocator->next = *bin;
	*bin = allocator;
	return r;
}

static void* mp_tcache_malloc_small_fast(mp_tcache* tcache, size_t size, uint_fast64_t flags)
{
	void* r;
	mp_block_allocator_intrusive** bin;
	mp_block_allocator_intrusive* allocator;
	uint_fast8_t sc;
	sc = mp_size_to_sc(size);
	MP_INVARIANT(sc < tcache_small_sc_count);
	bin = tcache->bins + sc;
	MP_UNLIKELY_IF(*bin == NULL)
	{
		MP_UNLIKELY_IF(mp_wcas_list_peek(tcache->recovered_small + sc) != NULL)
			*bin = (mp_block_allocator_intrusive*)mp_wcas_list_pop_all(tcache->recovered_small + sc);
		MP_UNLIKELY_IF(*bin == NULL && mp_wcas_list_peek(rcache_small + sc) != NULL)
			*bin = (mp_block_allocator_intrusive*)mp_wcas_list_pop(rcache_small + sc);
	}
	allocator = *bin;
	MP_LIKELY_IF(allocator != NULL)
	{
		r = mp_block_allocator_intrusive_malloc(allocator);
		MP_INVARIANT(r != NULL);
		MP_UNLIKELY_IF(allocator->free_count == 0)
		{
			MP_ATOMIC_CLEAR_REL(&allocator->linked);
			*bin = (*bin)->next;
		}
		return r;
	}
	else
	{
		MP_UNLIKELY_IF(flags & MP_NO_FALLBACK)
			return NULL;
		return mp_tcache_malloc_small_slow(tcache, size, sc);
	}
}

static void* mp_tcache_malloc_large_slow(mp_tcache* tcache, size_t size, uint_fast8_t sc)
{
	void* r;
	void* buffer;
	mp_block_allocator* allocator;
	mp_block_allocator** bin;
	uint_fast8_t bin_index;
	bin_index = mp_sc_large_bin_index(sc);
	MP_INVARIANT(this_tcache != NULL);
	buffer = mp_lcache_malloc(chunk_size, 0);
	MP_UNLIKELY_IF(buffer == NULL)
		return NULL;
	allocator = mp_tcache_insert_allocator(buffer);
	MP_UNLIKELY_IF(allocator == NULL)
		return NULL;
	mp_block_allocator_init(allocator, sc, this_tcache, buffer);
	r = mp_block_allocator_malloc(allocator);
	bin = tcache->bins_large + bin_index;
	allocator->next = *bin;
	*bin = allocator;
	return r;
}

static void* mp_tcache_malloc_large_fast(mp_tcache* tcache, size_t size, uint_fast64_t flags)
{
	void* r;
	mp_block_allocator** bin;
	mp_block_allocator* allocator;
	uint_fast8_t sc, bin_index;
	sc = mp_size_to_sc(size);
	bin_index = mp_sc_large_bin_index(sc);
	MP_INVARIANT(size == mp_sc_to_size(sc));
	bin = tcache->bins_large + bin_index;
	MP_UNLIKELY_IF(*bin == NULL)
	{
		MP_UNLIKELY_IF(mp_wcas_list_peek(tcache->recovered_large + bin_index) != NULL)
			*bin = (mp_block_allocator*)mp_wcas_list_pop_all(tcache->recovered_large + bin_index);
		MP_UNLIKELY_IF(*bin == NULL && mp_wcas_list_peek(rcache_large + bin_index) != NULL)
			*bin = (mp_block_allocator*)mp_wcas_list_pop(rcache_large + bin_index);
	}
	allocator = *bin;
	MP_LIKELY_IF(allocator != NULL)
	{
		r = mp_block_allocator_malloc(allocator);
		MP_INVARIANT(r != NULL);
		MP_UNLIKELY_IF(allocator->free_count == 0)
		{
			MP_ATOMIC_CLEAR_REL(&allocator->linked);
			*bin = (*bin)->next;
		}
		return r;
	}
	else
	{
		MP_UNLIKELY_IF(flags & MP_NO_FALLBACK)
			return NULL;
		return mp_tcache_malloc_large_slow(tcache, size, sc);
	}
}

// ================================================================
//	MAIN API
// ================================================================

MP_EXTERN_C_BEGIN
MP_ATTR mp_bool MP_CALL mp_init(const mp_init_options* options)
{
#ifdef MP_TARGET_WINDOWS
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	max_address = info.lpMaximumApplicationAddress;
	min_address = (void*)MP_ALIGN_CEIL_MASK((size_t)info.lpMinimumApplicationAddress, chunk_size - 1);
	page_size = info.dwPageSize;
	chunk_size = page_size * MP_CACHE_LINE_SIZE * 8;
	large_page_size = GetLargePageMinimum();
#else
	page_size = (size_t)getpagesize();
	chunk_size = page_size * MP_CACHE_LINE_SIZE * 8;
	large_page_size = gethugepagesize();
#endif
#ifdef MP_DEBUG
	(void)memset(&junkptr, MP_JUNK_VALUE, MP_PTR_SIZE);
#endif
	chunk_size_mask = chunk_size - 1;
	page_size_log2 = MP_FLOOR_LOG2(page_size);
	chunk_size_log2 = MP_FLOOR_LOG2(chunk_size);
	MP_INVARIANT(page_size_log2 >= 12);
	MP_INVARIANT(chunk_size_log2 >= 20);
	tcache_small_sc_count = MP_SIZE_CLASS_COUNT + 1 + (page_size_log2 - 12);
	tcache_large_sc_count = chunk_size_log2 - (page_size_log2 + 1);
#ifndef MP_NO_CUSTOM_BACKEND
	MP_UNLIKELY_IF(options->backend != NULL)
	{
		MP_INVARIANT(
			backend_init != NULL && backend_cleanup != NULL && backend_malloc != NULL &&
			backend_resize != NULL && backend_free != NULL && backend_purge != NULL);
		backend_init = options->backend->init;
		backend_cleanup = options->backend->cleanup;
		backend_malloc = options->backend->malloc;
		backend_resize = options->backend->resize;
		backend_free = options->backend->free;
		backend_purge = options->backend->purge;
	}
	MP_UNLIKELY_IF(!backend_init(options))
		return MP_FALSE;
#else
	MP_INVARIANT(options->backend == NULL);
	mp_os_init(options);
#endif
	mp_lcache_init();
	mp_rcache_init();
#ifdef MP_32BIT
	mp_tcache_lookup_init();
#else
	mp_init_flag = MP_TRUE;
#endif
	return MP_TRUE;
}

MP_ATTR mp_bool MP_CALL mp_init_default()
{
	mp_init_options opt;
	(void)memset(&opt, 0, sizeof(mp_init_options));
	return mp_init(&opt);
}

MP_ATTR mp_bool MP_CALL mp_enabled()
{
#ifdef MP_32BIT
	return lcache_bins != NULL;
#else
	return mp_init_flag;
#endif
}

MP_ATTR void MP_CALL mp_cleanup()
{
	mp_persistent_cleanup_impl(&public_persistent_allocator);
#ifdef MP_DEBUG
	mp_debug_enabled_flag = MP_FALSE;
#endif
#ifdef MP_64BIT
	mp_init_flag = MP_FALSE;
#endif
}

MP_ATTR void MP_CALL mp_thread_init()
{
	MP_INVARIANT(this_tcache == NULL);
	this_tcache = mp_tcache_acquire();
}

MP_ATTR mp_bool MP_CALL mp_thread_enabled()
{
	return this_tcache != NULL;
}

MP_ATTR void MP_CALL mp_thread_cleanup()
{
	uint_fast8_t i;
	mp_block_allocator* allocator;
	mp_block_allocator_intrusive* allocator_intrusive;
	MP_INVARIANT(this_tcache != NULL);
	MP_ATOMIC_CLEAR_REL(&this_tcache->is_active);
	for (i = 0; i != tcache_small_sc_count; ++i)
		for (allocator_intrusive = (mp_block_allocator_intrusive*)mp_wcas_list_pop_all(this_tcache->recovered_small + i); allocator_intrusive != NULL; allocator_intrusive = allocator_intrusive->next)
			mp_wcas_list_push(rcache_small + i, allocator_intrusive);
	for (i = 0; i != tcache_large_sc_count; ++i)
		for (allocator = (mp_block_allocator*)mp_wcas_list_pop_all(this_tcache->recovered_large + i); allocator != NULL; allocator = allocator->next)
			mp_wcas_list_push(rcache_large + i, allocator);
	for (i = 0; i != tcache_small_sc_count; ++i)
		for (allocator_intrusive = this_tcache->bins[i]; allocator_intrusive != NULL; allocator_intrusive = allocator_intrusive->next)
			mp_wcas_list_push(rcache_small + i, allocator_intrusive);
	for (i = 0; i != tcache_large_sc_count; ++i)
		for (allocator = this_tcache->bins_large[i]; allocator != NULL; allocator = allocator->next)
			mp_wcas_list_push(rcache_large + i, allocator);
	mp_tcache_release(this_tcache);
	this_tcache = NULL;
}

MP_ATTR void* MP_CALL mp_malloc(size_t size)
{
	void* r;
	size_t k;
	k = mp_round_size(MP_SIZE_WITH_REDZONE(size));
	MP_INVARIANT(k >= MP_SIZE_WITH_REDZONE(size));
	MP_LIKELY_IF(k <= mp_tcache_max_size())
		r = mp_tcache_malloc(k, 0);
	else
		r = mp_lcache_malloc(k, 0);
	mp_init_redzone(r, size);
	return r;
}

MP_ATTR mp_bool MP_CALL mp_resize_sized(void* ptr, size_t old_size, size_t new_size)
{
	MP_INVARIANT(ptr != NULL);
	MP_LIKELY_IF(MP_ALIGN_CEIL(old_size, chunk_size / 2) < old_size)
		return mp_tcache_resize(ptr, old_size, new_size, 0);
	else
		return mp_lcache_resize(ptr, old_size, new_size, 0);
}

MP_ATTR void* MP_CALL mp_realloc_sized(void* ptr, size_t old_size, size_t new_size)
{
	void* r;
	MP_INVARIANT(ptr != NULL);
#ifdef MP_DEBUG
	assert(mp_debug_overflow_check(ptr, old_size));
#endif
	MP_UNLIKELY_IF(mp_resize_sized(ptr, old_size, new_size))
		return ptr;
	r = mp_malloc(new_size);
	MP_LIKELY_IF(r != NULL)
	{
		(void)memcpy(r, ptr, old_size);
		mp_free_sized(ptr, old_size);
	}
	MP_DEBUG_JUNK_FILL((uint8_t*)r + old_size, new_size - old_size);
	mp_init_redzone(r, new_size);
	return r;
}

MP_ATTR void MP_CALL mp_free_sized(void* ptr, size_t size)
{
	size_t k;
	mp_fn_free fn;
	MP_INVARIANT(ptr != NULL);
	k = mp_round_size(MP_SIZE_WITH_REDZONE(size));
	MP_INVARIANT(k >= MP_SIZE_WITH_REDZONE(size));
#ifdef MP_DEBUG
	assert(mp_debug_overflow_check(ptr, size));
#endif
	fn = mp_tcache_free;
	MP_LIKELY_IF(k > mp_tcache_max_size())
		fn = mp_lcache_free;
	fn(ptr, k);
}

#ifdef MP_LEGACY_COMPATIBLE
MP_ATTR size_t MP_CALL mp_block_size_of(void* ptr)
{
	abort();
}

MP_ATTR mp_bool MP_CALL mp_resize(void* ptr, size_t new_size)
{
	size_t old_size = mp_block_size_of(ptr);
	return mp_resize_sized(ptr, old_size, new_size);
}

MP_NODISCARD MP_ATTR void* MP_CALL mp_realloc(void* ptr, size_t new_size)
{
	size_t old_size = mp_block_size_of(ptr);
	return mp_realloc_sized(ptr, old_size, new_size);
}

MP_ATTR void MP_CALL mp_free(void* ptr)
{
	size_t size = mp_block_size_of(ptr);
	return mp_free_sized(ptr, size);
}
#endif

MP_ATTR size_t MP_CALL mp_round_size(size_t size)
{
	MP_LIKELY_IF(size <= mp_tcache_max_size())
		return mp_tcache_round_size(size);
	else
		return mp_lcache_round_size(size);
}

MP_ATTR void* MP_CALL mp_tcache_malloc(size_t size, mp_flags flags)
{
	void* r;
	size_t k;
	MP_INVARIANT(this_tcache != NULL);
	mp_this_tcache_check_integrity();
	k = mp_round_size(size);
	if (size <= page_size)
		r = mp_tcache_malloc_small_fast(this_tcache, k, flags);
	else
		r = mp_tcache_malloc_large_fast(this_tcache, k, flags);
	MP_DEBUG_JUNK_FILL(r, size);
	mp_this_tcache_check_integrity();
	return r;
}

MP_ATTR mp_bool MP_CALL mp_tcache_resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags)
{
	return mp_tcache_round_size(MP_SIZE_WITH_REDZONE(old_size)) == mp_tcache_round_size(MP_SIZE_WITH_REDZONE(new_size));
}

MP_ATTR void MP_CALL mp_tcache_free(void* ptr, size_t size)
{
	MP_INVARIANT(ptr != NULL);
	mp_block_allocator_intrusive* allocator_intrusive;
	mp_block_allocator* allocator;
	size_t k;
	mp_this_tcache_check_integrity();
	size = mp_round_size(size);
	MP_LIKELY_IF(size <= page_size)
	{
		k = mp_chunk_size_of(size);
		allocator_intrusive = (mp_block_allocator_intrusive*)MP_ALIGN_FLOOR((size_t)ptr, k);
		MP_LIKELY_IF(allocator_intrusive->owner == this_tcache)
			mp_block_allocator_intrusive_free(allocator_intrusive, ptr);
		else
			mp_block_allocator_intrusive_free_shared(allocator_intrusive, ptr);
	}
	else
	{
		allocator = mp_tcache_find_allocator(ptr);
		MP_INVARIANT(allocator != NULL);
		MP_LIKELY_IF(allocator->owner == this_tcache)
			mp_block_allocator_free(allocator, ptr);
		else
			mp_block_allocator_free_shared(allocator, ptr);
	}
	mp_this_tcache_check_integrity();
}

MP_ATTR size_t MP_CALL mp_tcache_round_size(size_t size)
{
	size_t r, step;
	uint_fast8_t i, j;
	MP_UNLIKELY_IF(size == 0)
		return 1;
	MP_UNLIKELY_IF(size >= page_size)
		return MP_CEIL_POW2(size);
	i = MP_FLOOR_LOG2(size);
	r = (size_t)1 << i;
	step = (size_t)1 << MP_SIZE_MAP_ALIGNMENT_LOG2S[i];
	for (j = 0; j != MP_SIZE_MAP_SUBCLASS_COUNTS[i]; ++j)
	{
		MP_UNLIKELY_IF(r >= size)
			return r;
		r += step;
	}
	return (size_t)1 << (i + 1);
}

MP_ATTR size_t MP_CALL mp_tcache_min_size()
{
	return 0;
}

MP_ATTR size_t MP_CALL mp_tcache_max_size()
{
	return chunk_size / 2;
}

MP_ATTR void* MP_CALL mp_lcache_malloc(size_t size, mp_flags flags)
{
	void* r;
	mp_chunk_list* bin;
	size_t total, peak;
	MP_INVARIANT((size & chunk_size_mask) == 0);
	r = NULL;
	bin = mp_lcache_find_bin(size);
	MP_LIKELY_IF(bin != NULL)
		r = mp_chunk_list_pop(bin);
	MP_UNLIKELY_IF(r == NULL && !(flags & MP_NO_FALLBACK))
		r = mp_backend_malloc(size);
	MP_UNLIKELY_IF(r == NULL)
		return NULL;
	(void)MP_ATOMIC_FAA_REL(&lcache_active_memory, size);
	total = MP_ATOMIC_FAA_REL(&lcache_total_memory, size);
	total += size;
	MP_SPIN_LOOP
	{
		peak = MP_ATOMIC_LOAD_ACQ_UPTR(&lcache_peak_memory);
		MP_LIKELY_IF(peak > total || MP_ATOMIC_CMPXCHG_REL_UPTR(&lcache_peak_memory, &peak, total))
			break;
	}
	MP_DEBUG_JUNK_FILL(r, size);
	return r;
}

MP_ATTR mp_bool MP_CALL mp_lcache_resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags)
{
	MP_LIKELY_IF(mp_lcache_round_size(MP_SIZE_WITH_REDZONE(old_size)) == mp_lcache_round_size(MP_SIZE_WITH_REDZONE(new_size)))
		return MP_TRUE;
	return mp_backend_resize(ptr, old_size, new_size);
}

MP_ATTR void MP_CALL mp_lcache_free(void* ptr, size_t size)
{
	MP_INVARIANT(ptr != NULL);
	mp_chunk_list* bin;
	bin = mp_lcache_insert_bin(size);
	MP_INVARIANT(bin != NULL);
	mp_chunk_list_push(bin, ptr);
	(void)MP_ATOMIC_FAS_REL(&lcache_active_memory, size);
}

MP_ATTR size_t MP_CALL mp_lcache_round_size(size_t size)
{
	return MP_ALIGN_CEIL_MASK(size, chunk_size_mask);
}

MP_ATTR size_t MP_CALL mp_lcache_min_size()
{
	return chunk_size;
}

MP_ATTR size_t MP_CALL mp_lcache_max_size()
{
	return UINTPTR_MAX;
}

MP_ATTR void* MP_CALL mp_persistent_malloc(size_t size)
{
	void* r;
	r = mp_persistent_malloc_impl(&internal_persistent_allocator, size);
	MP_DEBUG_JUNK_FILL(r, size);
	return r;
}

MP_ATTR void MP_CALL mp_persistent_cleanup()
{
	mp_persistent_cleanup_impl(&public_persistent_allocator);
}

MP_ATTR void* MP_CALL mp_backend_malloc(size_t size)
{
	void* r;
	size_t k;
	k = mp_round_size(MP_SIZE_WITH_REDZONE(size));
#ifndef MP_NO_CUSTOM_BACKEND
	MP_INVARIANT(backend_malloc != NULL);
	r = backend_malloc(k);
#else
	r = mp_os_malloc(k);
#endif
	MP_DEBUG_JUNK_FILL(r, size);
	mp_init_redzone(r, size);
	return r;
}

MP_ATTR mp_bool MP_CALL mp_backend_resize(void* ptr, size_t old_size, size_t new_size)
{
	size_t k;
	MP_INVARIANT(ptr != NULL);
	mp_debug_overflow_check(ptr, old_size);
	k = mp_round_size(MP_SIZE_WITH_REDZONE(new_size));
#ifndef MP_NO_CUSTOM_BACKEND
	MP_INVARIANT(backend_resize != NULL);
	MP_UNLIKELY_IF(backend_resize(ptr, old_size, k))
		return MP_FALSE;
#else
	MP_UNLIKELY_IF(mp_os_resize(ptr, old_size, k))
		return MP_FALSE;
#endif
	mp_init_redzone(ptr, new_size);
	MP_DEBUG_JUNK_FILL((uint8_t*)ptr + old_size, new_size - old_size);
	return MP_TRUE;
}

MP_ATTR void MP_CALL mp_backend_free(void* ptr, size_t size)
{
	MP_INVARIANT(ptr != NULL);
#ifndef MP_NO_CUSTOM_BACKEND
	MP_INVARIANT(backend_free != NULL);
	backend_free(ptr, size);
#else
	mp_os_free(ptr, size);
#endif
}

MP_ATTR void MP_CALL mp_backend_purge(void* ptr, size_t size)
{
	MP_INVARIANT(ptr != NULL);
#ifndef MP_NO_CUSTOM_BACKEND
	MP_INVARIANT(backend_purge != NULL);
	backend_purge(ptr, size);
#else
	mp_os_purge(ptr, size);
#endif
}

MP_ATTR size_t MP_CALL mp_backend_required_alignment()
{
	return chunk_size;
}

MP_ATTR void MP_CALL mp_debug_init(const mp_debug_options* options)
{
#ifdef MP_DEBUG
	(void)memcpy(&debugger, options, sizeof(mp_debug_options));
	mp_debug_enabled_flag = MP_TRUE;
#endif
}

MP_ATTR size_t MP_CALL mp_cache_line_size()
{
	return MP_CACHE_LINE_SIZE;
}

MP_ATTR size_t MP_CALL mp_page_size()
{
	return page_size;
}

MP_ATTR size_t MP_CALL mp_large_page_size()
{
	return large_page_size;
}

MP_ATTR void* MP_CALL mp_lowest_address()
{
	return min_address;
}

MP_ATTR void* MP_CALL mp_highest_address()
{
	return max_address;
}

MP_ATTR void MP_CALL mp_debug_init_default()
{
#ifdef MP_DEBUG
	debugger.context = NULL;
	debugger.message = mp_default_debug_message_callback;
	debugger.warning = mp_default_debug_warning_callback;
	debugger.error = mp_default_debug_error_callback;
	mp_debug_enabled_flag = MP_TRUE;
#endif
}

MP_ATTR mp_bool MP_CALL mp_debug_enabled()
{
#ifdef MP_DEBUG
	return mp_debug_enabled_flag;
#else
	return MP_FALSE;
#endif
}

MP_ATTR void MP_CALL mp_debug_message(const char* message, size_t size)
{
#ifdef MP_DEBUG
	debugger.message(debugger.context, message, size);
#endif
}

MP_ATTR void MP_CALL mp_debug_warning(const char* message, size_t size)
{
#ifdef MP_DEBUG
	debugger.warning(debugger.context, message, size);
#endif
}

MP_ATTR void MP_CALL mp_debug_error(const char* message, size_t size)
{
#ifdef MP_DEBUG
	debugger.error(debugger.context, message, size);
#endif
}

MP_ATTR mp_bool MP_CALL mp_debug_validate_memory(const void* ptr, size_t size)
{
	mp_block_allocator* allocator;
	mp_block_allocator_intrusive* allocator_intrusive;
	size_t n;
	MP_UNLIKELY_IF(mp_debug_overflow_check(ptr, size))
		return MP_FALSE;
	size = mp_round_size(MP_SIZE_WITH_REDZONE(size));
	if (size >= chunk_size)
		return MP_TRUE;
	if (size < page_size)
	{
		n = mp_chunk_size_of(size);
		allocator_intrusive = (mp_block_allocator_intrusive*)MP_ALIGN_FLOOR((size_t)ptr, n);
		return mp_is_valid_block_allocator_intrusive(allocator_intrusive);
	}
	else
	{
		allocator = mp_tcache_find_allocator(ptr);
		MP_UNLIKELY_IF(allocator == NULL)
			return MP_FALSE;
		return mp_is_valid_block_allocator(allocator);
	}
}

MP_ATTR mp_bool MP_CALL mp_debug_overflow_check(const void* ptr, size_t size)
{
#ifdef MP_CHECK_OVERFLOW
	MP_INVARIANT(ptr != NULL);
	const size_t* begin;
	const size_t* end;
	size_t expected;
	(void)memset(&expected, MP_REDZONE_VALUE, MP_PTR_SIZE);
	begin = (const size_t*)((const uint8_t*)ptr + size);
	end = begin + (MP_REDZONE_SIZE >> MP_PTR_SIZE_LOG2);
	for (; begin != end; ++begin)
		MP_UNLIKELY_IF(*begin != expected)
			return MP_FALSE;
#endif
	return MP_TRUE;
}
MP_EXTERN_C_END
#endif
#endif