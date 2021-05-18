/*
	Copyright 2021 Marcel Pi Nacy
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at
		http://www.apache.org/licenses/LICENSE-2.0
	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

#ifndef MP_INCLUDED
#define MP_INCLUDED

#include <stdint.h>
#include <stddef.h>

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

#ifndef MP_SPIN_THRESHOLD
#define MP_SPIN_THRESHOLD 16
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

#define MP_FALSE ((mp_bool)0)
#define MP_TRUE ((mp_bool)1)

MP_EXTERN_C_BEGIN
typedef enum mp_init_flag_bits
{
	MP_INIT_ENABLE_LARGE_PAGES = 63
} mp_init_flag_bits;
typedef uint64_t mp_init_flags;

typedef enum mp_malloc_flag_bits
{
	MP_ENABLE_FALLBACK = 1,
} mp_malloc_flag_bits;
typedef uint64_t mp_flags;

typedef enum mp_flush_type
{
	MP_FLUSH_FULL,
	MP_FLUSH_EXPONENTIAL,
} mp_flush_type;

typedef void(MP_PTR* mp_fn_init)();
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
	size_t used_memory;
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

MP_ATTR void				MP_CALL mp_init(const mp_init_options* options);
MP_ATTR void				MP_CALL mp_init_default();
MP_ATTR mp_bool				MP_CALL mp_enabled();
MP_ATTR void				MP_CALL mp_cleanup();
MP_ATTR void				MP_CALL mp_thread_init();
MP_ATTR mp_bool				MP_CALL mp_thread_enabled();
MP_ATTR void				MP_CALL mp_thread_cleanup();

MP_NODISCARD MP_ATTR void*	MP_CALL mp_malloc(size_t size);
MP_ATTR mp_bool				MP_CALL mp_resize(void* ptr, size_t old_size, size_t new_size);
MP_NODISCARD MP_ATTR void*	MP_CALL mp_realloc(void* ptr, size_t old_size, size_t new_size);
MP_ATTR void				MP_CALL mp_free(void* ptr, size_t size);
MP_ATTR size_t				MP_CALL mp_round_size(size_t size);

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

#if defined(__cplusplus) && defined(MP_CXX_API)
namespace mp
{
	using init_options = mp_init_options;
	using memory_stats = mp_heap_stats;
	using trim_options = mp_trim_options;
	using debug_options = mp_debug_options;

	MP_ATTR void			MP_CALL init(const mp_init_options* options) noexcept { return mp_init(options); }
	MP_ATTR void			MP_CALL init() noexcept { return mp_init_default(); }
	MP_ATTR void			MP_CALL cleanup() noexcept { mp_cleanup(); }
	MP_ATTR void*			MP_CALL malloc(size_t size) noexcept { return mp_malloc(size); }
	MP_ATTR bool			MP_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept { return mp_resize(ptr, old_size, new_size); }
	MP_ATTR void*			MP_CALL realloc(void* ptr, size_t old_size, size_t new_size) noexcept { return mp_realloc(ptr, old_size, new_size); }
	MP_ATTR void			MP_CALL free(void* ptr, size_t size) noexcept { mp_free(ptr, size); }
	MP_ATTR size_t			MP_CALL round_size(size_t size) noexcept { return mp_round_size(size); }

	namespace thread_cache
	{
		MP_ATTR void*		MP_CALL malloc(size_t size, mp_flags flags) noexcept { return mp_tcache_malloc(size, flags); }
		MP_ATTR bool		MP_CALL resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags) noexcept { return mp_tcache_resize(ptr, old_size, new_size, flags); }
		MP_ATTR void		MP_CALL free(void* ptr, size_t size) noexcept { mp_tcache_free(ptr, size); }
		MP_ATTR size_t		MP_CALL round_size(size_t size) noexcept { return mp_tcache_round_size(size); }
		MP_ATTR size_t		MP_CALL min_size() noexcept { return mp_tcache_min_size(); }
		MP_ATTR size_t		MP_CALL max_size() noexcept { return mp_tcache_max_size(); }
	}

	namespace large_cache
	{
		MP_ATTR void*		MP_CALL malloc(size_t size, mp_flags flags) noexcept { return mp_lcache_malloc(size, flags); }
		MP_ATTR bool		MP_CALL resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags) noexcept { return mp_lcache_resize(ptr, old_size, new_size, flags); }
		MP_ATTR void		MP_CALL free(void* ptr, size_t size) noexcept { mp_lcache_free(ptr, size); }
		MP_ATTR size_t		MP_CALL round_size(size_t size) noexcept { return mp_lcache_round_size(size); }
		MP_ATTR size_t		MP_CALL min_size() noexcept { return mp_lcache_min_size(); }
		MP_ATTR size_t		MP_CALL max_size() noexcept { return mp_lcache_max_size(); }
	}

	namespace persistent
	{
		MP_ATTR void*		MP_CALL malloc(size_t size) noexcept { return mp_persistent_malloc(size); }
		MP_ATTR void		MP_CALL cleanup() noexcept { mp_persistent_cleanup(); }
	}

	namespace backend
	{
		MP_ATTR size_t		MP_CALL required_alignment() noexcept { return mp_backend_required_alignment(); }
		MP_ATTR void*		MP_CALL malloc(size_t size) noexcept { return mp_backend_malloc(size); }
		MP_ATTR bool		MP_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept { return mp_backend_resize(ptr, old_size, new_size); }
		MP_ATTR void		MP_CALL free(void* ptr, size_t size) noexcept { return mp_backend_free(ptr, size); }
	}

	namespace debugger
	{
		MP_ATTR void		MP_CALL init(const debug_options* options) noexcept { return mp_debug_init((const mp_debug_options*)options); }
		MP_ATTR bool		MP_CALL enabled() noexcept { return mp_debug_enabled(); }
		MP_ATTR void		MP_CALL message(const char* message, size_t size) noexcept { return mp_debug_message(message, size); }
		MP_ATTR void		MP_CALL warning(const char* message, size_t size) noexcept { return mp_debug_warning(message, size); }
		MP_ATTR void		MP_CALL error(const char* message, size_t size) noexcept { return mp_debug_error(message, size); }
	}
}
#endif



#ifdef MP_IMPLEMENTATION
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

#ifndef MP_STRING_JOIN
#define MP_STRING_JOIN(LHS, RHS) LHS##RHS
#endif

#ifdef MP_CHECK_OVERFLOW
#define MP_SIZE_WITH_REDZONE(K) ((K) + MP_REDZONE_SIZE)
#else
#define MP_SIZE_WITH_REDZONE(K) (K)
#endif

#ifdef __cplusplus
#define MP_ALIGNAS(SIZE) alignas((SIZE))
#endif

#ifdef MP_DEBUG
#define MP_DEBUG_JUNK_FILL(P, K) MP_UNLIKELY_IF((P) != NULL) (void)memset((P), MP_JUNK_VALUE, (K))
#else
#define MP_DEBUG_JUNK_FILL(P, K)
#endif

#define MP_ALIGN_FLOOR_BASE(VALUE, MASK) ((VALUE) & ~(MASK))
#define MP_ALIGN_CEIL_BASE(VALUE, MASK) ((VALUE + (MASK)) & ~(MASK))
#define MP_ALIGN_FLOOR(VALUE, ALIGNMENT) MP_ALIGN_FLOOR_BASE(VALUE, (ALIGNMENT) - 1)
#define MP_ALIGN_CEIL(VALUE, ALIGNMENT) MP_ALIGN_CEIL_BASE(VALUE, (ALIGNMENT) - 1)

#ifdef __linux__
#define MP_TARGET_LINUX
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <hugetlbfs.h>
#elif defined(_WIN32)
#define MP_TARGET_WINDOWS
#include <Windows.h>
#include <ntsecapi.h>
#else
#error "MPMALLOC: UNSUPPORTED TARGET OPERATING SYSTEM"
#endif

#if defined(__clang__) || defined(__GNUC__)
#define MP_CLANG_OR_GCC
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define MP_SPIN_WAIT __builtin_ia32_pause()
#elif defined(__arm__)
#define MP_SPIN_WAIT __yield()
#elif defined(__POWERPC__)
#define MP_SPIN_WAIT asm volatile("or 31,31,31")
#else
#define MP_SPIN_WAIT
#endif
#ifndef __cplusplus
#define MP_ALIGNAS(SIZE) __attribute__((aligned((SIZE))))
#endif
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
#define MP_SPIN_WAIT _mm_pause()
#define MP_PREFETCH(PTR) _mm_prefetch((const CHAR*)(PTR), _MM_HINT_T0)
#elif defined(_M_ARM)
#define MP_SPIN_WAIT __yield()
#define MP_PREFETCH(PTR) __prefetch((const CHAR*)(PTR))
#elif defined(_M_PPC)
#define MP_SPIN_WAIT
#define MP_PREFETCH(PTR)
#else
#define MP_SPIN_WAIT
#define MP_PREFETCH(PTR)
#endif
#ifndef __cplusplus
#define MP_ALIGNAS(SIZE) __declspec(align(SIZE))
#endif
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
#define MP_INVARIANT assert
#define MP_UNREACHABLE abort()
#else
#define MP_INVARIANT MP_ASSUME
#define MP_UNREACHABLE MP_ASSUME(MP_FALSE)
#endif
#define MP_SPIN_LOOP for (;; MP_SPIN_WAIT)
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
#define MP_EMMIT_MESSAGE(MESSAGE) mp_debug_message((MESSAGE), (sizeof((MESSAGE)) / sizeof((MESSAGE)[0])) - 1)
#define MP_EMMIT_WARNING(MESSAGE) mp_debug_warning((MESSAGE), (sizeof((MESSAGE)) / sizeof((MESSAGE)[0])) - 1)
#define MP_EMMIT_ERROR(MESSAGE) mp_debug_error((MESSAGE), (sizeof((MESSAGE)) / sizeof((MESSAGE)[0])) - 1)
static_assert((MP_REDZONE_SIZE & ((UINTMAX_C(1) << MP_PTR_SIZE_LOG2) - UINTMAX_C(1))) == 0, "Error, MP_REDZONE_SIZE must be a multiple of sizeof(size_t).");
#else
#define MP_EMMIT_MESSAGE(MESSAGE)
#define MP_EMMIT_WARNING(MESSAGE)
#define MP_EMMIT_ERROR(MESSAGE)
#endif

// ================================================================
//	ATOMIC INTRINSICS
// ================================================================

#ifdef MP_CLANG_OR_GCC
#define MP_ATOMIC(TYPE) TYPE volatile
typedef MP_ATOMIC(mp_bool) mp_atomic_bool;
#define MP_ATOMIC_TEST_ACQ(WHERE)								__atomic_load_n((mp_atomic_bool*)(WHERE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_TAS_ACQ(WHERE)								__atomic_test_and_set((mp_atomic_bool*)(WHERE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_CLEAR_REL(WHERE)								__atomic_clear((mp_atomic_bool*)(WHERE), __ATOMIC_RELEASE)
#define MP_ATOMIC_LOAD_ACQ_UPTR(WHERE)							__atomic_load_n((mp_atomic_size_t*)(WHERE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_STORE_REL_UPTR(WHERE, VALUE)					__atomic_store_n((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_XCHG_ACQ_UPTR(WHERE, VALUE)					__atomic_exchange_n((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_CMPXCHG_ACQ_UPTR(WHERE, EXPECTED, VALUE)		__atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_ATOMIC_CMPXCHG_REL_UPTR(WHERE, EXPECTED, VALUE)		__atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_FALSE, __ATOMIC_RELEASE, __ATOMIC_RELAXED)
#define MP_ATOMIC_CMPXCHG_WEAK_ACQ_UPTR(WHERE, EXPECTED, VALUE)	__atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_TRUE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_ATOMIC_CMPXCHG_WEAK_REL_UPTR(WHERE, EXPECTED, VALUE)	__atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_TRUE, __ATOMIC_RELEASE, __ATOMIC_RELAXED)
#define MP_ATOMIC_FAA_ACQ(WHERE, VALUE)							__atomic_fetch_add((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_FAA_REL(WHERE, VALUE)							__atomic_fetch_add((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_FAS_ACQ(WHERE, VALUE)							__atomic_fetch_sub((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_FAS_REL(WHERE, VALUE)							__atomic_fetch_sub((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_BIT_SET_REL(WHERE, VALUE)						(void)__atomic_fetch_or((mp_atomic_size_t*)(WHERE), (size_t)1 << (uint_fast8_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_ACQUIRE_FENCE									__atomic_thread_fence(__ATOMIC_ACQUIRE)
#ifdef MP_32BIT
#define MP_ATOMIC_WCMPXCHG_ACQ(WHERE, EXPECTED, VALUE)			__atomic_compare_exchange_n((volatile int64_t*)(WHERE), (int64_t*)(EXPECTED), *(const int64_t*)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_ATOMIC_WCMPXCHG_REL(WHERE, EXPECTED, VALUE)			__atomic_compare_exchange_n((volatile int64_t*)(WHERE), (int64_t*)(EXPECTED), *(const int64_t*)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#else
#define MP_ATOMIC_WCMPXCHG_ACQ(WHERE, EXPECTED, VALUE)			__atomic_compare_exchange_n((volatile __int128*)(WHERE), (__int128*)(EXPECTED), *(const __int128*)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_ATOMIC_WCMPXCHG_REL(WHERE, EXPECTED, VALUE)			__atomic_compare_exchange_n((volatile __int128*)(WHERE), (__int128*)(EXPECTED), *(const __int128*)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#endif
#elif defined(MP_MSVC)
// I'd like to give special thanks to the visual studio dev team for being more than 10 years ahead of the competition in not adding support to the C11 standard to their compiler.
#define MP_ATOMIC(TYPE) TYPE volatile
typedef MP_ATOMIC(CHAR) mp_atomic_bool;
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
typedef CHAR mp_msvc_bool;
typedef volatile CHAR mp_msvc_atomic_bool;
typedef volatile mp_msvc_size_t mp_msvc_atomic_size_t;
#define MP_ATOMIC_TEST_ACQ(WHERE) (mp_bool)MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(_InterlockedOr8)((mp_msvc_atomic_bool*)(WHERE), (mp_msvc_bool)0)
#define MP_ATOMIC_TAS_ACQ(WHERE) (mp_bool)MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(_InterlockedExchange8)((mp_msvc_atomic_bool*)(WHERE), (mp_msvc_bool)1)
#define MP_ATOMIC_CLEAR_REL(WHERE) (void)MP_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(_InterlockedExchange8)((mp_msvc_atomic_bool*)(WHERE), (mp_msvc_bool)0)
#define MP_ATOMIC_LOAD_ACQ_UPTR(WHERE) MP_MSVC_ATOMIC_ACQ(_InterlockedOr)((mp_msvc_atomic_size_t*)(WHERE), 0)
#define MP_ATOMIC_STORE_REL_UPTR(WHERE, VALUE) (void)MP_MSVC_ATOMIC_REL(_InterlockedExchange)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_XCHG_ACQ_UPTR(WHERE, VALUE) MP_MSVC_ATOMIC_ACQ(_InterlockedExchange)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_CMPXCHG_ACQ_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_ACQ(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), *(const mp_msvc_size_t*)(VALUE), (mp_msvc_size_t)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_CMPXCHG_REL_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_REL(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), *(const mp_msvc_size_t*)(VALUE), (mp_msvc_size_t)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_CMPXCHG_WEAK_ACQ_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_ACQ(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), *(const mp_msvc_size_t*)(VALUE), (mp_msvc_size_t)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_CMPXCHG_WEAK_REL_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_REL(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), *(const mp_msvc_size_t*)(VALUE), (mp_msvc_size_t)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_FAA_ACQ(WHERE, VALUE) (size_t)MP_MSVC_ATOMIC_ACQ(_InterlockedExchangeAdd)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_FAA_REL(WHERE, VALUE) (size_t)MP_MSVC_ATOMIC_REL(_InterlockedExchangeAdd)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_FAS_ACQ(WHERE, VALUE) (size_t)MP_MSVC_ATOMIC_ACQ(_InterlockedExchangeAdd)((mp_msvc_atomic_size_t*)(WHERE), -(mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_FAS_REL(WHERE, VALUE) (size_t)MP_MSVC_ATOMIC_REL(_InterlockedExchangeAdd)((mp_msvc_atomic_size_t*)(WHERE), -(mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_BIT_SET_REL(WHERE, VALUE) (void)MP_MSVC_ATOMIC_REL(_interlockedbittestandset)((mp_msvc_atomic_size_t*)(WHERE), (uint_fast8_t)(VALUE))
#define MP_ATOMIC_ACQUIRE_FENCE MemoryBarrier()

typedef struct mp_msvc_uintptr_pair { MP_ALIGNAS(MP_DPTR_SIZE) size_t a, b; } mp_msvc_uintptr_pair;

MP_INLINE_ALWAYS static mp_bool mp_impl_cmpxchg16_acq(volatile mp_msvc_uintptr_pair* where, const mp_msvc_uintptr_pair* expected, const mp_msvc_uintptr_pair* desired)
{
#ifdef MP_32BIT
	return MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(_InterlockedCompareExchange64)((volatile LONG64*)where, *(const LONG64*)desired, *(const LONG64*)expected) == *(const LONG64*)expected;
#else
	mp_msvc_uintptr_pair tmp;
	(void)memcpy(&tmp, expected, 16);
	return (mp_bool)MP_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(_InterlockedCompareExchange128)((volatile LONG64*)where, desired->b, desired->b, (LONG64*)&tmp);
#endif
}

MP_INLINE_ALWAYS static mp_bool mp_impl_cmpxchg16_rel(volatile mp_msvc_uintptr_pair* where, const mp_msvc_uintptr_pair* expected, const mp_msvc_uintptr_pair* desired)
{
#ifdef MP_32BIT
	return MP_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(_InterlockedCompareExchange64)((volatile LONG64*)where, *(const LONG64*)desired, *(const LONG64*)expected) == *(const LONG64*)expected;
#else
	mp_msvc_uintptr_pair tmp;
	(void)memcpy(&tmp, expected, 16);
	return (mp_bool)MP_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(_InterlockedCompareExchange128)((volatile LONG64*)where, desired->b, desired->b, (LONG64*)&tmp);
#endif
}

#define MP_ATOMIC_WCMPXCHG_ACQ(WHERE, EXPECTED, VALUE) mp_impl_cmpxchg16_acq((volatile mp_msvc_uintptr_pair*)(WHERE), (const mp_msvc_uintptr_pair*)(EXPECTED), (const mp_msvc_uintptr_pair*)(VALUE))
#define MP_ATOMIC_WCMPXCHG_REL(WHERE, EXPECTED, VALUE) mp_impl_cmpxchg16_rel((volatile mp_msvc_uintptr_pair*)(WHERE), (const mp_msvc_uintptr_pair*)(EXPECTED), (const mp_msvc_uintptr_pair*)(VALUE))
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

// ================================================================
//	MISCELLANEOUS
// ================================================================

#define MP_ZERO_COLD_16(PTR) _mm_stream_si128((__m128i*)PTR, _mm_setzero_si128())
#define MP_ZERO_COLD_32(PTR) _mm256_stream_si256((__m256i*)PTR, _mm256_setzero_si256())
#define MP_ZERO_COLD_64(PTR) _mm512_stream_si512((__m512i*)PTR, _mm512_setzero_si512())

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

// ================================================================
//	MPMALLOC MAIN DATA TYPES
// ================================================================

typedef MP_ATOMIC(size_t) mp_atomic_size_t;
typedef MP_ATOMIC(void*) mp_atomic_address;

typedef struct mp_flist_node { struct mp_flist_node* next; } mp_flist_node;
typedef MP_ATOMIC(mp_flist_node*) mp_rlist;

#ifndef MP_STRICT_FREELIST
typedef size_t mp_chunk_list_head;
#else
typedef struct mp_chunk_list_head
{
	MP_ALIGNAS(MP_DPTR_SIZE) mp_flist_node* head;
	size_t counter;
} mp_chunk_list_head;
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
	uint8_t size_class;
	mp_atomic_bool linked;
	size_t free_map[MP_BLOCK_ALLOCATOR_MASK_COUNT];
	MP_SHARED_ATTR mp_atomic_size_t marked_map[MP_BLOCK_ALLOCATOR_MASK_COUNT];
} mp_block_allocator;

typedef struct mp_block_allocator_intrusive
{
	MP_SHARED_ATTR struct mp_block_allocator_intrusive* next;
	struct mp_tcache* owner;
	uint32_t free_count;
	uint8_t size_class;
	mp_atomic_bool linked;
	MP_SHARED_ATTR size_t free_map[MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT];
	MP_SHARED_ATTR mp_atomic_size_t marked_map[MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT];
} mp_block_allocator_intrusive;

typedef struct mp_tcache
{
	MP_SHARED_ATTR mp_block_allocator_intrusive** bins;
	mp_rlist* recovered;
	mp_block_allocator** bins_large;
	mp_rlist* recovered_large;
	struct mp_tcache* next;
	mp_heap_stats stats;
} mp_tcache;

static MP_TLS mp_tcache* this_tcache;

typedef struct mp_tcache_pool_head
{
	MP_ALIGNAS(MP_DPTR_SIZE) mp_tcache* head;
	size_t generation;
} mp_tcache_pool_head;

typedef struct mp_shared_counter { MP_SHARED_ATTR mp_atomic_size_t value; } mp_shared_counter;

// ================================================================
//	PLATFORM INFO
// ================================================================

static void* min_address;
static void* max_address;
static size_t page_size;
static size_t chunk_size;
static size_t chunk_size_mask;
static size_t tcache_large_bin_buffer_size;
static size_t tcache_buffer_size;
static size_t large_page_size;
static uint8_t page_size_log2;
static uint8_t chunk_size_log2;
#ifdef MP_64BIT
static mp_bool mp_init_flag;
#endif
#ifdef MP_DEBUG
static mp_debug_options debugger;
static mp_bool mp_debug_enabled_flag;
#endif

// ================================================================
//	SIZE CLASS MAPPING FUNCTIONS
// ================================================================

#ifdef __cplusplus
#define MP_CONST constexpr
#else
#define MP_CONST const
#endif

#define MP_SIZE_MAP_MAX 4096
#define MP_SIZE_MAP_MAX_LOG2 12
#define MP_SIZE_CLASS_COUNT 62
#define MP_TCACHE_SMALL_BIN_BUFFER_SIZE MP_PTR_SIZE * MP_SIZE_CLASS_COUNT

static MP_CONST uint16_t MP_SIZE_CLASSES[MP_SIZE_CLASS_COUNT] =
{
	1, 2, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64,
	80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
	272, 288, 304, 320, 352, 384, 416, 448, 480, 512,
	544, 576, 640, 704, 768, 832, 896, 960, 1024,
	1088, 1152, 1280, 1408, 1536, 1664, 1792, 1920, 2048,
	2176, 2304, 2560, 2816, 3072, 3328, 3584, 3840
};

static MP_CONST uint16_t MP_SIZE_MAP_0[] = { 1 };
static MP_CONST uint16_t MP_SIZE_MAP_1[] = { 2 };
static MP_CONST uint16_t MP_SIZE_MAP_2[] = { 4 };
static MP_CONST uint16_t MP_SIZE_MAP_3[] = { 8, 12 };
static MP_CONST uint16_t MP_SIZE_MAP_4[] = { 16, 20, 24, 28 };
static MP_CONST uint16_t MP_SIZE_MAP_5[] = { 32, 40, 48, 56 };
static MP_CONST uint16_t MP_SIZE_MAP_6[] = { 64, 80, 96, 112 };
static MP_CONST uint16_t MP_SIZE_MAP_7[] = { 128, 144, 160, 176, 192, 208, 224, 240 };
static MP_CONST uint16_t MP_SIZE_MAP_8[] = { 256, 272, 288, 304, 320, 352, 384, 416, 448, 480 };
static MP_CONST uint16_t MP_SIZE_MAP_9[] = { 512, 544, 576, 640, 704, 768, 832, 896, 960 };
static MP_CONST uint16_t MP_SIZE_MAP_10[] = { 1024, 1088, 1152, 1280, 1408, 1536, 1664, 1792, 1920 };
static MP_CONST uint16_t MP_SIZE_MAP_11[] = { 2048, 2176, 2304, 2560, 2816, 3072, 3328, 3584, 3840 };

static const uint16_t* const MP_SIZE_MAP[MP_SIZE_MAP_MAX_LOG2] =
{
	MP_SIZE_MAP_0, MP_SIZE_MAP_1, MP_SIZE_MAP_2, MP_SIZE_MAP_3,
	MP_SIZE_MAP_4, MP_SIZE_MAP_5, MP_SIZE_MAP_6, MP_SIZE_MAP_7,
	MP_SIZE_MAP_8, MP_SIZE_MAP_9, MP_SIZE_MAP_10, MP_SIZE_MAP_11
};

static MP_CONST uint8_t MP_SIZE_MAP_SIZES[MP_SIZE_MAP_MAX_LOG2] =
{
	MP_ARRAY_SIZE(MP_SIZE_MAP_0), MP_ARRAY_SIZE(MP_SIZE_MAP_1), MP_ARRAY_SIZE(MP_SIZE_MAP_2), MP_ARRAY_SIZE(MP_SIZE_MAP_3),
	MP_ARRAY_SIZE(MP_SIZE_MAP_4), MP_ARRAY_SIZE(MP_SIZE_MAP_5), MP_ARRAY_SIZE(MP_SIZE_MAP_6), MP_ARRAY_SIZE(MP_SIZE_MAP_7),
	MP_ARRAY_SIZE(MP_SIZE_MAP_8), MP_ARRAY_SIZE(MP_SIZE_MAP_9), MP_ARRAY_SIZE(MP_SIZE_MAP_10), MP_ARRAY_SIZE(MP_SIZE_MAP_11)
};

static uint8_t MP_SIZE_MAP_OFFSETS[MP_SIZE_MAP_MAX_LOG2];
static uint32_t MP_SIZE_MAP_RESERVED_COUNTS[MP_SIZE_CLASS_COUNT];

MP_ULTRAPURE MP_INLINE_ALWAYS static uint_fast16_t mp_reserved_count_of(uint_fast8_t sc)
{
	MP_INVARIANT(sc < MP_SIZE_CLASS_COUNT);
	return (sizeof(mp_block_allocator_intrusive) + ((size_t)MP_SIZE_CLASSES[sc] - 1)) / MP_SIZE_CLASSES[sc];
}

MP_ULTRAPURE MP_INLINE_ALWAYS static uint_fast8_t mp_get_small_sc(size_t size)
{
	uint_fast8_t log2, i;
	log2 = MP_FLOOR_LOG2(size);
	if (log2 < MP_SIZE_MAP_MAX_LOG2)
	{
		for (i = 0; i != MP_SIZE_MAP_SIZES[log2]; ++i)
			MP_LIKELY_IF(MP_SIZE_MAP[log2][i] >= size)
				return MP_SIZE_MAP_OFFSETS[log2] + i;
	}
	return MP_CEIL_LOG2(size) - MP_SIZE_MAP_MAX_LOG2;
}

MP_ULTRAPURE MP_INLINE_ALWAYS static uint_fast32_t mp_get_large_sc(size_t size)
{
	return MP_CEIL_LOG2(size) - page_size_log2;
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

static HANDLE process_handle;
static VirtualAlloc2_t virtualalloc2;
static ULONG va2_flags;
static MEM_ADDRESS_REQUIREMENTS va2_addr_req;
static MEM_EXTENDED_PARAMETER va2_ext_param;

MP_INLINE_ALWAYS static void mp_os_init(mp_bool enable_large_pages)
{
	HANDLE h;
	DWORD n;
	TOKEN_USER users[64];
	LSA_HANDLE policy;
	LSA_OBJECT_ATTRIBUTES attrs;
	LSA_UNICODE_STRING rights;
	TOKEN_PRIVILEGES p;
	process_handle = GetCurrentProcess();
	virtualalloc2 = (VirtualAlloc2_t)GetProcAddress(GetModuleHandle(TEXT("KernelBase.DLL")), "VirtualAlloc2");
	MP_INVARIANT(virtualalloc2 != NULL);
	va2_addr_req.Alignment = chunk_size;
	va2_addr_req.HighestEndingAddress = max_address;
	va2_addr_req.LowestStartingAddress = min_address;
	va2_ext_param.Type = MemExtendedParameterAddressRequirements;
	va2_ext_param.Pointer = &va2_addr_req;
	va2_flags = MEM_RESERVE | MEM_COMMIT;
	if (!enable_large_pages)
		return;
	h = NULL;
	MP_UNLIKELY_IF(!OpenProcessToken(process_handle, TOKEN_QUERY, &h))
		goto Error;
	n = sizeof(users);
	MP_UNLIKELY_IF(!GetTokenInformation(h, TokenUser, users, n, &n))
		goto Error;
	CloseHandle(h);
	(void)memset(&attrs, 0, sizeof(attrs));
	MP_UNLIKELY_IF(!LsaOpenPolicy(NULL, &attrs, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &policy))
		goto Error;
	rights.Buffer = (PWSTR)SE_LOCK_MEMORY_NAME;
	rights.Length = (USHORT)(wcslen(rights.Buffer) * sizeof(WCHAR));
	rights.MaximumLength = rights.Length + (USHORT)sizeof(WCHAR);
	MP_UNLIKELY_IF(!LsaAddAccountRights(policy, users->User.Sid, &rights, 1))
		goto Error;
	h = NULL;
	MP_UNLIKELY_IF(!OpenProcessToken(process_handle, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h))
		goto Error;
	p.PrivilegeCount = 1;
	p.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	MP_UNLIKELY_IF(!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &p.Privileges[0].Luid))
		goto Error;
	MP_UNLIKELY_IF(!AdjustTokenPrivileges(h, FALSE, &p, 0, NULL, 0))
		goto Error;
	va2_flags |= MEM_LARGE_PAGES;
	CloseHandle(h);
	return;
Error:
	abort();
}

MP_INLINE_ALWAYS static void* mp_os_malloc(size_t size)
{
	return virtualalloc2(process_handle, NULL, size, va2_flags, PAGE_READWRITE, &va2_ext_param, 1);
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
	uint8_t* r = (uint8_t*)MP_ALIGN_FLOOR_BASE((size_t)tmp, chunk_size_mask);
	uint8_t* r_limit = base + chunk_size;
	MP_LIKELY_IF(tmp != r)
		munmap(tmp, r - tmp);
	MP_LIKELY_IF(tmp_limit != r_limit)
		munmap(base_limit, tmp_limit - r_limit);
	return base;
}

MP_INLINE_ALWAYS static void mp_os_free(void* ptr, size_t size)
{
	MP_INVARIANT(ptr != NULL);
	munmap(ptr, size);
}

MP_INLINE_ALWAYS static void mp_os_purge(void* ptr, size_t size)
{
	MP_INVARIANT(ptr != NULL);
	madvise(ptr, size, MADV_DONTNEED);
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
//	LOCK-FREE CHUNK FREE LIST
// ================================================================

MP_INLINE_ALWAYS static void mp_chunk_list_push(mp_chunk_list* head, void* ptr)
{
	mp_flist_node* new_head;
	mp_chunk_list_head prior, desired;
	new_head = (mp_flist_node*)ptr;
#ifdef MP_STRICT_FREELIST
	desired.head = new_head;
#endif
	MP_SPIN_LOOP
	{
#ifndef MP_STRICT_FREELIST
		prior = MP_ATOMIC_LOAD_ACQ_UPTR(head);
		new_head->next = (mp_flist_node*)(prior & ~chunk_size_mask);
		desired = (size_t)new_head | (((prior & chunk_size_mask) + 1) & chunk_size_mask);
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_WEAK_REL_UPTR(head, &prior, desired))
			break;
#else
		(void)memcpy(&prior, (void*)head, MP_DPTR_SIZE);
		MP_ATOMIC_ACQUIRE_FENCE;
		new_head->next = prior.head;
		desired.counter = prior.counter + 1;
		MP_LIKELY_IF(MP_ATOMIC_WCMPXCHG_ACQ(head, &prior, &desired))
			break;
#endif
	}
}

MP_INLINE_ALWAYS static void* mp_chunk_list_pop(mp_chunk_list* head)
{
	mp_flist_node* r;
	mp_chunk_list_head prior, desired;
	MP_SPIN_LOOP
	{
#ifndef MP_STRICT_FREELIST
		prior = MP_ATOMIC_LOAD_ACQ_UPTR(head);
		r = (mp_flist_node*)(prior & ~chunk_size_mask);
		MP_UNLIKELY_IF(r == NULL)
			return NULL;
		desired = (size_t)r->next | (((prior & chunk_size_mask) + 1) & chunk_size_mask);
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_WEAK_ACQ_UPTR(head, &prior, desired))
			return r;
#else
		(void)memcpy(&prior, (void*)head, MP_DPTR_SIZE);
		MP_ATOMIC_ACQUIRE_FENCE;
		r = prior.head;
		MP_UNLIKELY_IF(r == NULL)
			return NULL;
		desired.head = r->next;
		desired.counter = prior.counter + 1;
		MP_LIKELY_IF(MP_ATOMIC_WCMPXCHG_REL(head, &prior, &desired))
			return r;
#endif
	}
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
		return mp_lcache_malloc(MP_ALIGN_CEIL_BASE(size, chunk_size_mask), MP_ENABLE_FALLBACK);
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
	n = (mp_persistent_node*)mp_lcache_malloc(chunk_size, MP_ENABLE_FALLBACK);
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
	size_t k;
	k = sizeof(mp_tcache) + tcache_buffer_size;
	buffer = (uint8_t*)mp_persistent_malloc_impl(&internal_persistent_allocator, k);
	MP_INVARIANT(buffer != NULL);
#if defined(MP_DEBUG) || !defined(MP_NO_CUSTOM_BACKEND)
	(void)memset(buffer, 0, k);
#endif
	r = (mp_tcache*)buffer;
	buffer += sizeof(mp_tcache);
	r->bins = (mp_block_allocator_intrusive**)buffer;
	buffer += MP_TCACHE_SMALL_BIN_BUFFER_SIZE;
	r->recovered = (mp_rlist*)buffer;
	buffer += MP_TCACHE_SMALL_BIN_BUFFER_SIZE;
	r->bins_large = (mp_block_allocator**)buffer;
	buffer += tcache_large_bin_buffer_size;
	r->recovered_large = (mp_rlist*)buffer;
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
//	BLOCK ALLOCATOR
// ================================================================

MP_INLINE_ALWAYS static void mp_block_allocator_init(mp_block_allocator* allocator, uint_fast8_t sc, struct mp_tcache* owner, void* buffer)
{
	uint_fast32_t mask_count, bit_count;
	mp_zero_fill_block_allocator_marked_map((void*)allocator->marked_map);
	MP_PREFETCH(buffer);
	MP_INVARIANT(allocator != NULL);
	MP_INVARIANT(buffer != NULL);
	allocator->next = NULL;
	allocator->free_count = 1U << (chunk_size_log2 - (sc + page_size_log2));
	allocator->size_class = sc;
	allocator->owner = owner;
	allocator->buffer = (uint8_t*)buffer;
	MP_NON_ATOMIC_SET(allocator->linked);
	(void)memset(allocator->free_map, 0, MP_CACHE_LINE_SIZE / 2);
	mask_count = allocator->free_count >> MP_PTR_BITS_LOG2;
	bit_count = allocator->free_count & MP_PTR_BITS_MASK;
	(void)memset(allocator->free_map, 0xff, (size_t)mask_count * MP_PTR_SIZE);
	allocator->free_map[mask_count] |= ((size_t)1 << bit_count) - (size_t)1;
}

MP_INLINE_ALWAYS static void mp_block_allocator_intrusive_init(mp_block_allocator_intrusive* allocator, uint_fast8_t sc, struct mp_tcache* owner)
{
	uint_fast32_t mask_count, bit_count, reserved_count;
	MP_INVARIANT(allocator != NULL);
	mp_zero_fill_block_allocator_intrusive_marked_map((void*)allocator->marked_map);
	MP_INVARIANT(sc < MP_SIZE_CLASS_COUNT);
	reserved_count = MP_SIZE_MAP_RESERVED_COUNTS[sc];
	MP_INVARIANT(reserved_count == mp_reserved_count_of(sc));
	MP_PREFETCH((uint8_t*)allocator + (size_t)reserved_count * MP_SIZE_CLASSES[allocator->size_class]);
	allocator->next = NULL;
	MP_INVARIANT(reserved_count >= 1);
	allocator->free_count = MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY - reserved_count;
	MP_INVARIANT(reserved_count < allocator->free_count);
	allocator->size_class = sc;
	allocator->owner = owner;
	MP_NON_ATOMIC_SET(allocator->linked);
	(void)memset(allocator->free_map, 0xff, MP_CACHE_LINE_SIZE);
	mask_count = reserved_count >> MP_PTR_BITS_LOG2;
	bit_count = reserved_count & MP_PTR_BITS_MASK;
	(void)memset(allocator->free_map, 0, mask_count);
	allocator->free_map[mask_count] &= ~(((size_t)1 << bit_count) - (size_t)1);
}

MP_ULTRAPURE MP_INLINE_ALWAYS static size_t mp_chunk_size_of_small(size_t size)
{
	MP_INVARIANT(size != 0);
	return MP_CEIL_POW2(size * MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY);
}

MP_ULTRAPURE MP_INLINE_ALWAYS static size_t mp_chunk_size_of_large(size_t size)
{
	MP_INVARIANT(size != 0);
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
		(allocator->size_class + page_size_log2) != 0 && allocator->size_class < (chunk_size_log2 - page_size_log2) &&
		(uint8_t)allocator->linked < 2;
}

MP_PURE MP_INLINE_ALWAYS static mp_bool mp_is_valid_block_allocator_intrusive(mp_block_allocator_intrusive* allocator)
{
	return
		allocator->owner != NULL && allocator->free_count < MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY &&
		MP_SIZE_CLASSES[allocator->size_class] != 0 && allocator->size_class < MP_SIZE_CLASS_COUNT &&
		(uint8_t)allocator->linked < 2;
}

MP_PURE MP_INLINE_ALWAYS static uint_fast32_t mp_block_allocator_index_of(mp_block_allocator* allocator, void* ptr)
{
	MP_INVARIANT(mp_is_valid_block_allocator(allocator));
	return (uint_fast32_t)(((size_t)((uint8_t*)ptr - (uint8_t*)allocator->buffer)) >> (allocator->size_class + page_size_log2));
}

MP_PURE MP_INLINE_ALWAYS static uint_fast32_t mp_block_allocator_intrusive_index_of(mp_block_allocator_intrusive* allocator, void* ptr)
{
	MP_INVARIANT(mp_is_valid_block_allocator_intrusive(allocator));
	return (uint_fast32_t)(((size_t)((uint8_t*)ptr - (uint8_t*)allocator)) / MP_SIZE_CLASSES[allocator->size_class]);
}

MP_INLINE_ALWAYS static mp_bool mp_block_allocator_owns(mp_block_allocator* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_is_valid_block_allocator(allocator));
	MP_UNLIKELY_IF((uint8_t*)ptr < (uint8_t*)allocator->buffer)
		return MP_FALSE;
	MP_UNLIKELY_IF((uint8_t*)ptr >= (uint8_t*)allocator->buffer + mp_chunk_size_of_large((size_t)1 << (allocator->size_class + page_size_log2)))
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
	MP_UNLIKELY_IF((uint8_t*)ptr >= (uint8_t*)allocator + mp_chunk_size_of_small(MP_SIZE_CLASSES[allocator->size_class]))
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
	freed_count = 0;
	for (i = 0; i != bitmask_count; ++i)
	{
		MP_UNLIKELY_IF(MP_ATOMIC_LOAD_ACQ_UPTR(marked_map + i) == 0)
			continue;
		mask = MP_ATOMIC_XCHG_ACQ_UPTR(marked_map + i, 0);
		freed_count += MP_POPCOUNT(mask);
		free_map[i] |= mask;
	}
	return freed_count;
}

MP_INLINE_NEVER static uint_fast32_t mp_block_allocator_reclaim(size_t* free_map, mp_atomic_size_t* marked_map, uint_fast32_t bitmask_count)
{
	return mp_block_allocator_reclaim_inline(free_map, marked_map, bitmask_count);
}

MP_INLINE_ALWAYS static void* mp_block_allocator_malloc(mp_block_allocator* allocator)
{
	uint_fast32_t mask_index, bit_index;
	MP_INVARIANT(allocator->linked != 0);
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
		allocator->free_count += mp_block_allocator_reclaim(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_MASK_COUNT);
	return allocator->buffer + ((((size_t)mask_index << MP_PTR_BITS_LOG2) | bit_index) << (allocator->size_class + page_size_log2));
}

MP_INLINE_ALWAYS static void* mp_block_allocator_intrusive_malloc(mp_block_allocator_intrusive* allocator)
{
	uint_fast32_t mask_index, bit_index;
	MP_INVARIANT(allocator->linked != 0);
	MP_INVARIANT(allocator->free_count != 0);
	for (mask_index = 0; mask_index != MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT; ++mask_index)
		MP_UNLIKELY_IF(allocator->free_map[mask_index] != 0)
			break;
	MP_INVARIANT(mask_index != MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT);
	bit_index = MP_CTZ(allocator->free_map[mask_index]);
	MP_INVARIANT(MP_BT(allocator->free_map[mask_index], bit_index));
	MP_BR(allocator->free_map[mask_index], bit_index);
	--allocator->free_count;
	MP_UNLIKELY_IF(allocator->free_count == 0)
		allocator->free_count += mp_block_allocator_reclaim(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT);
	return (uint8_t*)allocator + ((((size_t)mask_index << MP_PTR_BITS_LOG2) | bit_index) * MP_SIZE_CLASSES[allocator->size_class]);
}

typedef void (*mp_fn_block_allocator_recover)(void* bin, void* allocator, mp_atomic_bool* linked);

MP_INLINE_NEVER static void mp_block_allocator_recover(mp_flist_node** bin, mp_block_allocator* allocator)
{
	mp_flist_node* desired;
	MP_UNLIKELY_IF(allocator->free_count == 0)
		allocator->free_count += mp_block_allocator_reclaim_inline(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_MASK_COUNT);
	MP_INVARIANT(allocator->free_count != 0);
	MP_UNLIKELY_IF(allocator->free_count == MP_BLOCK_ALLOCATOR_MAX_CAPACITY)
		return mp_lcache_free(allocator, chunk_size);
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
	MP_UNLIKELY_IF(allocator->free_count == MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY - MP_SIZE_MAP_RESERVED_COUNTS[allocator->size_class])
		return mp_free(allocator, mp_chunk_size_of_small(MP_SIZE_CLASSES[allocator->size_class]));
	desired = (mp_flist_node*)allocator;
	desired->next = *bin;
	*bin = desired;
}

MP_INLINE_NEVER static void mp_block_allocator_recover_shared(mp_rlist* recovered, mp_block_allocator* allocator)
{
	mp_flist_node* desired;
	// At this point only the current thread can access this block allocator, so we can do this:
	MP_UNLIKELY_IF(allocator->free_count == 0)
		allocator->free_count += mp_block_allocator_reclaim_inline(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_MASK_COUNT);
	MP_INVARIANT(allocator->free_count != 0);
	MP_UNLIKELY_IF(allocator->free_count == MP_BLOCK_ALLOCATOR_MAX_CAPACITY)
		return mp_lcache_free(allocator, chunk_size);
	desired = (mp_flist_node*)allocator;
	MP_SPIN_LOOP
	{
		desired->next = (mp_flist_node*)MP_ATOMIC_LOAD_ACQ_PTR(recovered);
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_WEAK_REL_PTR(recovered, &desired->next, desired)) // ABA issue
			break;
	}
}

MP_INLINE_NEVER static void mp_block_allocator_intrusive_recover_shared(mp_rlist* recovered, mp_block_allocator_intrusive* allocator)
{
	mp_flist_node* desired;
	// Same with mp_block_allocator_intrusive_recover_shared:
	MP_UNLIKELY_IF(allocator->free_count == 0)
		allocator->free_count += mp_block_allocator_reclaim_inline(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT);
	MP_INVARIANT(allocator->free_count != 0);
	MP_UNLIKELY_IF(allocator->free_count == MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY - MP_SIZE_MAP_RESERVED_COUNTS[allocator->size_class])
		return mp_free(allocator, mp_chunk_size_of_small(MP_SIZE_CLASSES[allocator->size_class]));
	desired = (mp_flist_node*)allocator;
	MP_SPIN_LOOP
	{
		desired->next = (mp_flist_node*)MP_ATOMIC_LOAD_ACQ_PTR(recovered);
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_WEAK_REL_PTR(recovered, &desired->next, desired)) // ABA issue
			break;
	}
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
		mp_block_allocator_intrusive_recover_shared(allocator->owner->recovered + allocator->size_class, allocator);
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
		mp_block_allocator_recover((mp_flist_node**)(allocator->owner->bins_large + allocator->size_class), allocator);
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
		mp_block_allocator_recover_shared(allocator->owner->recovered_large + allocator->size_class, allocator);
}

MP_INLINE_ALWAYS static mp_block_allocator_intrusive* mp_tcache_block_allocator_intrusive_allocator_of(const void* ptr, size_t chunk_size)
{
	return (mp_block_allocator_intrusive*)MP_ALIGN_FLOOR((size_t)ptr, chunk_size);
}

// ================================================================
//	64-BIT VAS CHUNK DIGITAL TREE
// ================================================================

#ifdef MP_64BIT
#define MP_TRIE_ROOT_SIZE 256
typedef uint8_t* mp_trie_leaf;
typedef MP_ATOMIC(mp_trie_leaf)* mp_trie_branch;
typedef MP_ATOMIC(mp_trie_branch) mp_trie_root;
static size_t branch_size;
static size_t branch_mask;
static size_t leaf_size;
static size_t leaf_mask;
static uint8_t leaf_log2;
static uint8_t branch_log2;

static void* mp_trie_find(mp_trie_root* root, size_t key, uint_fast8_t value_size_log2)
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
	branch = (mp_trie_branch)MP_ATOMIC_LOAD_ACQ_PTR(root + root_index);
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

static void* mp_trie_insert(mp_trie_root* root, size_t key, uint_fast8_t value_size_log2)
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
	root += root_index;
	MP_SPIN_LOOP
	{
		branch = (mp_trie_branch)MP_ATOMIC_LOAD_ACQ_PTR(root);
		MP_LIKELY_IF(branch != NULL)
			break;
		new_branch = (mp_trie_branch)mp_lcache_malloc(real_branch_size, MP_ENABLE_FALLBACK);
		MP_UNLIKELY_IF(new_branch == NULL)
			return NULL;
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_REL_PTR(root, &branch, new_branch))
		{
			branch = new_branch;
			(void)memset((size_t*)branch, 0, real_branch_size);
			break;
		}
		mp_lcache_free((void*)new_branch, real_branch_size);
	}
	branch += branch_index;
	MP_SPIN_LOOP
	{
		leaf = (mp_trie_leaf)MP_ATOMIC_LOAD_ACQ_PTR(branch);
		MP_LIKELY_IF(leaf != NULL)
			break;
		new_leaf = (mp_trie_leaf)mp_lcache_malloc(real_leaf_size, MP_ENABLE_FALLBACK);
		MP_UNLIKELY_IF(new_leaf == NULL)
			return NULL;
		MP_LIKELY_IF(MP_ATOMIC_CMPXCHG_REL_PTR(branch, &leaf, new_leaf))
		{
			leaf = new_leaf;
			break;
		}
		mp_lcache_free(new_leaf, real_leaf_size);
	}
	offset = leaf_index << value_size_log2;
	MP_INVARIANT(offset + (1ULL << value_size_log2) <= real_leaf_size);
	leaf += offset;
	return leaf;
}
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
static mp_trie_root lcache_bin_roots[MP_TRIE_ROOT_SIZE];
#endif

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
	size -= size != 0;
#ifdef MP_32BIT
	return lcache_bins + size;
#else
	return (mp_chunk_list*)mp_trie_find(lcache_bin_roots, size, MP_FLOOR_LOG2(sizeof(mp_chunk_list)));
#endif
}

MP_INLINE_ALWAYS static mp_chunk_list* mp_lcache_insert_bin(size_t size)
{
#ifdef MP_32BIT
	return mp_lcache_find_bin(size);
#else
	size >>= chunk_size_log2;
	size -= size != 0;
	return (mp_chunk_list*)mp_trie_insert(lcache_bin_roots, size, MP_FLOOR_LOG2(sizeof(mp_chunk_list)));
#endif
}

// ================================================================
//	THREAD CACHE
// ================================================================

#ifdef MP_32BIT
static mp_block_allocator* tcache_lookup;
#else
static mp_trie_root tcache_lookup_roots[MP_TRIE_ROOT_SIZE];
#endif

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
	return (mp_block_allocator*)mp_trie_find(lcache_bin_roots, id, MP_CEIL_LOG2(sizeof(mp_block_allocator)));
#endif
}

MP_INLINE_ALWAYS static mp_block_allocator* mp_tcache_insert_allocator(const void* ptr)
{
#ifdef MP_32BIT
	return mp_tcache_find_allocator(ptr);
#else
	size_t id;
	id = (size_t)ptr >> chunk_size_log2;
	return (mp_block_allocator*)mp_trie_insert(lcache_bin_roots, id, MP_CEIL_LOG2(sizeof(mp_block_allocator)));
#endif
}

MP_INLINE_NEVER static void* mp_tcache_malloc_small_slow(mp_tcache* tcache, size_t size, uint_fast8_t sc)
{
	void* r;
	size_t k;
	mp_block_allocator_intrusive* allocator;
	mp_block_allocator_intrusive** bin;
	bin = tcache->bins + sc;
	MP_INVARIANT(this_tcache != NULL);
	k = mp_chunk_size_of_small(size);
	allocator = (mp_block_allocator_intrusive*)mp_malloc(k);
	MP_UNLIKELY_IF(allocator == NULL)
		return NULL;
	mp_block_allocator_intrusive_init(allocator, sc, this_tcache);
	r = mp_block_allocator_intrusive_malloc(allocator);
	allocator->next = *bin;
	*bin = allocator;
	return r;
}

MP_INLINE_NEVER static void* mp_tcache_malloc_large_slow(mp_tcache* tcache, size_t size, uint_fast8_t sc)
{
	void* r;
	void* buffer;
	mp_block_allocator* allocator;
	mp_block_allocator** bin;
	MP_INVARIANT(this_tcache != NULL);
	buffer = mp_lcache_malloc(chunk_size, MP_ENABLE_FALLBACK);
	MP_UNLIKELY_IF(buffer == NULL)
		return NULL;
	allocator = mp_tcache_insert_allocator(buffer);
	MP_UNLIKELY_IF(allocator == NULL)
		return NULL;
	mp_block_allocator_init(allocator, sc, this_tcache, buffer);
	r = mp_block_allocator_malloc(allocator);
	bin = tcache->bins_large + sc;
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
	sc = mp_get_small_sc(size);
	MP_INVARIANT(sc < MP_SIZE_CLASS_COUNT);
	bin = tcache->bins + sc;
	MP_UNLIKELY_IF(*bin == NULL && MP_ATOMIC_LOAD_ACQ_PTR(tcache->recovered + sc) != NULL)
		*bin = (mp_block_allocator_intrusive*)MP_ATOMIC_XCHG_ACQ_PTR(tcache->recovered + sc, NULL);
	allocator = *bin;
	MP_UNLIKELY_IF(allocator == NULL)
		return (flags & MP_ENABLE_FALLBACK) ? mp_tcache_malloc_small_slow(tcache, size, sc) : NULL;
	r = mp_block_allocator_intrusive_malloc(allocator);
	MP_INVARIANT(r != NULL);
	MP_UNLIKELY_IF(allocator->free_count == 0)
	{
		MP_ATOMIC_CLEAR_REL(&allocator->linked);
		*bin = (*bin)->next;
	}
	return r;
}

static void* mp_tcache_malloc_large_fast(mp_tcache* tcache, size_t size, uint_fast64_t flags)
{
	void* r;
	mp_block_allocator** bin;
	mp_block_allocator* allocator;
	uint_fast8_t sc;
	sc = mp_get_large_sc(size);
	MP_INVARIANT(sc < chunk_size_log2 - page_size_log2);
	MP_INVARIANT(size == ((size_t)1 << (sc + page_size_log2)));
	bin = tcache->bins_large + sc;
	MP_UNLIKELY_IF(*bin == NULL && MP_ATOMIC_LOAD_ACQ_PTR(tcache->recovered_large + sc) != NULL)
		*bin = (mp_block_allocator*)MP_ATOMIC_XCHG_ACQ_PTR(tcache->recovered_large + sc, NULL);
	allocator = *bin;
	MP_UNLIKELY_IF(allocator == NULL)
		return (flags & MP_ENABLE_FALLBACK) ? mp_tcache_malloc_large_slow(tcache, size, sc) : NULL;
	r = mp_block_allocator_malloc(allocator);
	MP_INVARIANT(r != NULL);
	MP_UNLIKELY_IF(allocator->free_count == 0)
	{
		MP_ATOMIC_CLEAR_REL(&allocator->linked);
		*bin = (*bin)->next;
	}
	return r;
}

MP_INLINE_ALWAYS static void mp_this_tcache_check_integrity()
{
#ifdef MP_DEBUG
	mp_block_allocator_intrusive* intrusive_allocator;
	mp_block_allocator* allocator;
	size_t i;
	for (i = 0; i != MP_SIZE_CLASS_COUNT; ++i)
		for (intrusive_allocator = this_tcache->bins[i]; intrusive_allocator != NULL; intrusive_allocator = intrusive_allocator->next)
			MP_INVARIANT(mp_is_valid_block_allocator_intrusive(intrusive_allocator));
	for (i = 0; i != (size_t)chunk_size_log2 - page_size_log2; ++i)
		for (allocator = this_tcache->bins_large[i]; allocator != NULL; allocator = allocator->next)
			MP_INVARIANT(mp_is_valid_block_allocator(allocator));
#endif
}

// ================================================================
//	MAIN API
// ================================================================

MP_EXTERN_C_BEGIN
MP_ATTR void MP_CALL mp_init(const mp_init_options* options)
{
	uint32_t i, n;
#ifdef MP_TARGET_WINDOWS
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	max_address = info.lpMaximumApplicationAddress;
	min_address = (void*)MP_ALIGN_CEIL_BASE((size_t)info.lpMinimumApplicationAddress, chunk_size - 1);
	page_size = info.dwPageSize;
	chunk_size = page_size * MP_CACHE_LINE_SIZE * 8;
	large_page_size = GetLargePageMinimum();
#else
	page_size = (size_t)getpagesize();
	chunk_size = page_size * MP_CACHE_LINE_SIZE * 8;
	large_page_size = gethugepagesize();
#endif
	chunk_size_mask = chunk_size - 1;
	page_size_log2 = MP_FLOOR_LOG2(page_size);
	chunk_size_log2 = MP_FLOOR_LOG2(chunk_size);
	MP_INVARIANT(page_size >= 4096);
	MP_INVARIANT(chunk_size >= (32 * 4096));
	tcache_large_bin_buffer_size = MP_PTR_SIZE * ((size_t)chunk_size_log2 - page_size_log2);
	tcache_buffer_size = (MP_TCACHE_SMALL_BIN_BUFFER_SIZE + tcache_large_bin_buffer_size) * 2;
	n = i = 0;
	for (; i != MP_SIZE_MAP_MAX_LOG2; ++i)
	{
		MP_SIZE_MAP_OFFSETS[i] = n;
		n += MP_SIZE_MAP_SIZES[i];
	}
	for (i = 0; i != MP_SIZE_CLASS_COUNT; ++i)
		MP_SIZE_MAP_RESERVED_COUNTS[i] = (sizeof(mp_block_allocator_intrusive) + ((size_t)MP_SIZE_CLASSES[i] - 1)) / MP_SIZE_CLASSES[i];
#ifndef MP_NO_CUSTOM_BACKEND
	MP_UNLIKELY_IF(options->backend != NULL)
	{
		MP_INVARIANT(
			backend_init != NULL && backend_cleanup != NULL &&
			backend_malloc != NULL && backend_resize != NULL &&
			backend_free != NULL && backend_purge != NULL);
		backend_init = options->backend->init;
		backend_cleanup = options->backend->cleanup;
		backend_malloc = options->backend->malloc;
		backend_resize = options->backend->resize;
		backend_free = options->backend->free;
		backend_purge = options->backend->purge;
	}
	backend_init();
#else
	MP_INVARIANT(options->backend == NULL);
	mp_os_init((options->flags & MP_INIT_ENABLE_LARGE_PAGES) != 0);
#endif
	mp_lcache_init();
#ifdef MP_32BIT
	mp_tcache_lookup_init();
#else
	mp_init_flag = MP_TRUE;
#endif
}

MP_ATTR void MP_CALL mp_init_default()
{
	mp_init_options opt;
	(void)memset(&opt, 0, sizeof(mp_init_options));
	mp_init(&opt);
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
	MP_INVARIANT(this_tcache != NULL);
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
		r = mp_tcache_malloc(k, MP_ENABLE_FALLBACK);
	else
		r = mp_lcache_malloc(k, MP_ENABLE_FALLBACK);
	mp_init_redzone(r, size);
	return r;
}

MP_ATTR mp_bool MP_CALL mp_resize(void* ptr, size_t old_size, size_t new_size)
{
	MP_INVARIANT(ptr != NULL);
	MP_LIKELY_IF(MP_ALIGN_CEIL(old_size, chunk_size / 2) < old_size)
		return mp_tcache_resize(ptr, old_size, new_size, MP_ENABLE_FALLBACK);
	else
		return mp_lcache_resize(ptr, old_size, new_size, MP_ENABLE_FALLBACK);
}

MP_ATTR void* MP_CALL mp_realloc(void* ptr, size_t old_size, size_t new_size)
{
	void* r;
	MP_INVARIANT(ptr != NULL);
	MP_INVARIANT(mp_debug_overflow_check(ptr, old_size));
	MP_UNLIKELY_IF(mp_resize(ptr, old_size, new_size))
		return ptr;
	r = mp_malloc(new_size);
	MP_LIKELY_IF(r != NULL)
	{
		(void)memcpy(r, ptr, old_size);
		mp_free(ptr, old_size);
	}
	MP_DEBUG_JUNK_FILL((uint8_t*)r + old_size, new_size - old_size);
	mp_init_redzone(r, new_size);
	return r;
}

MP_ATTR void MP_CALL mp_free(void* ptr, size_t size)
{
	size_t k;
	MP_INVARIANT(ptr != NULL);
	k = mp_round_size(MP_SIZE_WITH_REDZONE(size));
	MP_INVARIANT(k >= MP_SIZE_WITH_REDZONE(size));
	MP_INVARIANT(mp_debug_overflow_check(ptr, size));
	MP_LIKELY_IF(k <= mp_tcache_max_size())
		mp_tcache_free(ptr, k);
	else
		mp_lcache_free(ptr, k);
}

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
	mp_this_tcache_check_integrity();
	MP_DEBUG_JUNK_FILL(r, size);
	return r;
}

MP_ATTR mp_bool MP_CALL mp_tcache_resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags)
{
	return mp_tcache_round_size(MP_SIZE_WITH_REDZONE(old_size)) == mp_tcache_round_size(MP_SIZE_WITH_REDZONE(new_size));
}

MP_ATTR void MP_CALL mp_tcache_free(void* ptr, size_t size)
{
	mp_block_allocator_intrusive* intrusive_allocator;
	mp_block_allocator* allocator;
	size_t k;
	mp_this_tcache_check_integrity();
	size = mp_round_size(size);
	MP_LIKELY_IF(size <= page_size)
	{
		k = mp_chunk_size_of_small(size);
		intrusive_allocator = mp_tcache_block_allocator_intrusive_allocator_of(ptr, k);
		MP_INVARIANT(intrusive_allocator != NULL);
		MP_LIKELY_IF(intrusive_allocator->owner == this_tcache)
			mp_block_allocator_intrusive_free(intrusive_allocator, ptr);
		else
			mp_block_allocator_intrusive_free_shared(intrusive_allocator, ptr);
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
	uint_fast8_t log2, i;
	MP_INVARIANT(size <= chunk_size / 2);
	log2 = MP_FLOOR_LOG2(size);
	MP_LIKELY_IF(log2 < MP_SIZE_MAP_MAX_LOG2)
	{
		for (i = 0; i < MP_SIZE_MAP_SIZES[log2]; ++i)
			MP_LIKELY_IF(MP_SIZE_MAP[log2][i] >= size)
				return MP_SIZE_MAP[log2][i];
	}
	return MP_CEIL_POW2(size);
}

MP_ATTR size_t MP_CALL mp_tcache_min_size() { return 1; }
MP_ATTR size_t MP_CALL mp_tcache_max_size() { return chunk_size / 2; }

MP_ATTR void* MP_CALL mp_lcache_malloc(size_t size, mp_flags flags)
{
	void* r;
	mp_chunk_list* bin;
	r = NULL;
	bin = mp_lcache_find_bin(size);
	MP_LIKELY_IF(bin != NULL)
		r = mp_chunk_list_pop(bin);
	MP_UNLIKELY_IF(r == NULL && (flags & MP_ENABLE_FALLBACK))
		r = mp_backend_malloc(size);
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
	mp_chunk_list* bin;
	bin = mp_lcache_insert_bin(size);
	MP_INVARIANT(bin != NULL);
	mp_chunk_list_push(bin, ptr);
}

MP_ATTR size_t MP_CALL mp_lcache_round_size(size_t size)
{
	return MP_ALIGN_CEIL_BASE(size, chunk_size_mask);
}

MP_ATTR size_t MP_CALL mp_lcache_min_size() { return chunk_size; }
MP_ATTR size_t MP_CALL mp_lcache_max_size() { return UINTPTR_MAX; }

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
	size_t k;
	MP_UNLIKELY_IF(mp_debug_overflow_check(ptr, size))
		return MP_FALSE;
	k = mp_round_size(MP_SIZE_WITH_REDZONE(size));
	if (size > chunk_size)
		return MP_TRUE;
	if (size < page_size)
	{
		allocator_intrusive = mp_tcache_block_allocator_intrusive_allocator_of(ptr, mp_chunk_size_of_small(size));
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
	MP_INVARIANT(ptr != NULL);
#ifdef MP_CHECK_OVERFLOW
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