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
typedef void(MP_PTR *mp_fn_debugger_message)(void* context, const char* message, size_t size);
typedef void(MP_PTR *mp_fn_debugger_warning)(void* context, const char* message, size_t size);
typedef void(MP_PTR *mp_fn_debugger_error)(void* context, const char* message, size_t size);

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
	size_t expected_concurrency;
	const mp_backend_options* backend;
} mp_init_options;

typedef struct mp_mem_stats
{
	size_t allocation_count;
	size_t deallocation_count;
	size_t active_memory;
	size_t idle_memory;
	size_t record_concurrency;
} mp_mem_stats;

typedef struct mp_trim_options
{
	size_t trim_limit;
} mp_trim_options;

typedef struct mp_debugger_options
{
	void* context;
	mp_fn_debugger_message message;
	mp_fn_debugger_warning warning;
	mp_fn_debugger_error error;
} mp_debugger_options;

typedef struct mp_global_params
{
	size_t page_size;
	size_t chunk_size;
	size_t expected_concurrency;
} mp_global_params;

MP_ATTR void				MP_CALL mp_init_info_default(mp_init_options* out_options);
MP_ATTR void				MP_CALL mp_trim_options_default(mp_trim_options* out_options);
MP_ATTR void				MP_CALL mp_debugger_options_default(mp_debugger_options* out_options);

MP_ATTR void				MP_CALL mp_init(const mp_init_options* options);
MP_ATTR mp_bool				MP_CALL mp_is_initialized();
MP_ATTR void				MP_CALL mp_cleanup();
MP_ATTR void				MP_CALL mp_thread_init();
MP_ATTR void				MP_CALL mp_thread_cleanup();

MP_ATTR void				MP_CALL mp_stats(mp_mem_stats* out_stats);
MP_ATTR void				MP_CALL mp_params(mp_global_params* out_params);

MP_NODISCARD MP_ATTR void*	MP_CALL mp_malloc(size_t size);
MP_ATTR mp_bool				MP_CALL mp_resize(void* ptr, size_t old_size, size_t new_size);
MP_NODISCARD MP_ATTR void*	MP_CALL mp_realloc(void* ptr, size_t old_size, size_t new_size);
MP_ATTR void				MP_CALL mp_free(void* ptr, size_t size);
MP_ATTR size_t				MP_CALL mp_round_size(size_t size);
MP_ATTR size_t				MP_CALL mp_purge(mp_flags flags, void* param);
MP_ATTR size_t				MP_CALL mp_trim(const mp_trim_options* options);

MP_NODISCARD MP_ATTR void*	MP_CALL mp_tcache_malloc(size_t size, mp_flags flags);
MP_ATTR void				MP_CALL mp_tcache_free(void* ptr, size_t size);
MP_ATTR size_t				MP_CALL mp_tcache_round_size(size_t size);
MP_ATTR size_t				MP_CALL mp_tcache_flush(mp_flags flags, void* param);
MP_ATTR size_t				MP_CALL mp_tcache_min_size();
MP_ATTR size_t				MP_CALL mp_tcache_max_size();

MP_NODISCARD MP_ATTR void*	MP_CALL mp_lcache_malloc(size_t size, mp_flags flags);
MP_ATTR void				MP_CALL mp_lcache_free(void* ptr, size_t size);
MP_ATTR size_t				MP_CALL mp_lcache_round_size(size_t size);
MP_ATTR size_t				MP_CALL mp_lcache_flush(mp_flags flags, void* param);
MP_ATTR size_t				MP_CALL mp_lcache_min_size();
MP_ATTR size_t				MP_CALL mp_lcache_max_size();

MP_NODISCARD MP_ATTR void*	MP_CALL mp_persistent_malloc(size_t size);
MP_ATTR void				MP_CALL mp_persistent_cleanup();

MP_ATTR size_t				MP_CALL mp_backend_required_alignment();
MP_NODISCARD MP_ATTR void*	MP_CALL mp_backend_malloc(size_t size);
MP_ATTR mp_bool				MP_CALL mp_backend_resize(void* ptr, size_t old_size, size_t new_size);
MP_ATTR void				MP_CALL mp_backend_free(void* ptr, size_t size);
MP_ATTR void				MP_CALL mp_backend_purge(void* ptr, size_t size);

MP_ATTR void				MP_CALL mp_debug_init(const mp_debugger_options* options);
MP_ATTR mp_bool				MP_CALL mp_debug_enabled();
MP_ATTR void				MP_CALL mp_debug_message(const char* message, size_t size);
MP_ATTR void				MP_CALL mp_debug_warning(const char* message, size_t size);
MP_ATTR void				MP_CALL mp_debug_error(const char* message, size_t size);
MP_ATTR mp_bool				MP_CALL mp_debug_validate_memory(const void* ptr, size_t size);
MP_ATTR mp_bool				MP_CALL mp_debug_overflow_check(const void* ptr, size_t size);
MP_EXTERN_C_END

#if defined(__cplusplus) && defined(MP_CXX_API)
namespace mpmm
{
	struct init_options : mp_init_options
	{
		inline MP_ATTR MP_CALL init_options() noexcept { mp_init_info_default((mp_init_options*)this); }
		~init_options() = default;
	};

	using memory_stats = mp_mem_stats;

	struct trim_options : mp_trim_options
	{
		inline MP_ATTR MP_CALL trim_options() noexcept { mp_trim_options_default((mp_trim_options*)this); }
		~trim_options() = default;
	};

	struct debugger_options : mp_debugger_options
	{
		inline MP_ATTR MP_CALL debugger_options() noexcept { mp_debugger_options_default((mp_debugger_options*)this); }
		~debugger_options() = default;
	};

	MP_ATTR void			MP_CALL init(const mp_init_options* options) noexcept { return mp_init(options); }
	MP_ATTR void			MP_CALL cleanup() noexcept { mp_cleanup(); }
	MP_ATTR memory_stats	MP_CALL stats() noexcept { mp_mem_stats r; mp_stats(&r); return r; }
	MP_ATTR void*			MP_CALL malloc(size_t size) noexcept { return mp_malloc(size); }
	MP_ATTR bool			MP_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept { return mp_resize(ptr, old_size, new_size); }
	MP_ATTR void*			MP_CALL realloc(void* ptr, size_t old_size, size_t new_size) noexcept { return mp_realloc(ptr, old_size, new_size); }
	MP_ATTR void			MP_CALL free(void* ptr, size_t size) noexcept { mp_free(ptr, size); }
	MP_ATTR size_t			MP_CALL round_size(size_t size) noexcept { return mp_round_size(size); }
	MP_ATTR size_t			MP_CALL purge(mp_flags flags, void* param) noexcept { return mp_purge(flags, param); }
	MP_ATTR size_t			MP_CALL trim(const trim_options* options) noexcept { return mp_trim((const mp_trim_options*)options); }

	namespace thread_cache
	{
		MP_ATTR void*		MP_CALL malloc(size_t size, mp_flags flags) noexcept { return mp_tcache_malloc(size, flags); }
		MP_ATTR void		MP_CALL free(void* ptr, size_t size) noexcept { mp_tcache_free(ptr, size); }
		MP_ATTR size_t		MP_CALL round_size(size_t size) noexcept { return mp_tcache_round_size(size); }
		MP_ATTR size_t		MP_CALL flush(mp_flags flags, void* param) noexcept { return mp_tcache_flush(flags, param); }
		MP_ATTR size_t		MP_CALL min_size() noexcept { return mp_tcache_min_size(); }
		MP_ATTR size_t		MP_CALL max_size() noexcept { return mp_tcache_max_size(); }
	}

	namespace large_cache
	{
		MP_ATTR void*		MP_CALL malloc(size_t size, mp_flags flags) noexcept { return mp_lcache_malloc(size, flags); }
		MP_ATTR void		MP_CALL free(void* ptr, size_t size) noexcept { mp_lcache_free(ptr, size); }
		MP_ATTR size_t		MP_CALL round_size(size_t size) noexcept { return mp_lcache_round_size(size); }
		MP_ATTR size_t		MP_CALL flush(mp_flags flags, void* param) noexcept { return mp_lcache_flush(flags, param); }
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
		MP_ATTR void		MP_CALL purge(void* ptr, size_t size) noexcept { return mp_backend_free(ptr, size); }
	}

	namespace debugger
	{
		MP_ATTR void		MP_CALL init(const debugger_options* options) noexcept { return mp_debug_init((const mp_debugger_options*)options); }
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
#define MP_PTR_SIZE 4ULL
#define MP_PTR_SIZE_LOG2 2
#define MP_DPTR_SIZE 8ULL
#else
#define MP_64BIT
#define MP_PTR_SIZE 8ULL
#define MP_PTR_SIZE_LOG2 3
#define MP_DPTR_SIZE 16ULL
#endif

#define MP_PTR_SIZE_MASK (MP_PTR_SIZE - 1)

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
#define MP_TLS thread_local
#else
#define MP_TLS _Thread_local
#endif

#ifdef MP_DEBUG
#define MP_DEBUG_JUNK_FILL(P, K) MP_UNLIKELY_IF((P) != NULL) (void)memset((P), MP_JUNK_VALUE, (K))
#else
#define MP_DEBUG_JUNK_FILL(P, K)
#endif

#define MP_ALIGN_FLOOR(VALUE, ALIGNMENT) ((VALUE) & ~((ALIGNMENT) - 1))
#define MP_ALIGN_CEIL(VALUE, ALIGNMENT) ((VALUE + ((ALIGNMENT) - 1)) & ~((ALIGNMENT) - 1))
#define MP_ALIGN_FLOOR_LOG2(VALUE, ALIGNMENT_LOG2) MP_ALIGN_FLOOR(VALUE, ((size_t)1 << (size_t)ALIGNMENT_LOG2))
#define MP_ALIGN_CEIL_LOG2(VALUE, ALIGNMENT_LOG2) MP_ALIGN_CEIL(VALUE, ((size_t)1 << (size_t)ALIGNMENT_LOG2))

#ifdef _WIN32
#define MP_WINDOWS
#include <Windows.h>
#elif defined(__linux__) || defined(__LINUX__)
#define MP_LINUX
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#else
#error "MPMALLOC: UNSUPPORTED OS"
#endif

#if defined(__clang__) || defined(__GNUC__)
#define MP_CLANG_OR_GCC
#if defined(__x86_64__) || defined(__i386__)
#define MP_SPIN_WAIT __builtin_ia32_pause()
#elif defined(__arm__)
#define MP_SPIN_WAIT __yield()
#endif
#ifndef __cplusplus
#define MP_ALIGNAS(SIZE) __attribute__((aligned((SIZE))))
#endif
#define MP_PURE __attribute__((pure))
#define MP_ULTRAPURE __attribute__((const))
#define MP_PREFETCH(PTR) __builtin_prefetch((PTR), 1, 3)
#define MP_EXPECT(CONDITION, VALUE) __builtin_expect((long)(CONDITION), (VALUE))
#define MP_LIKELY_IF(CONDITION) if (MP_EXPECT(CONDITION, MP_TRUE))
#define MP_UNLIKELY_IF(CONDITION) if (MP_EXPECT(CONDITION, MP_FALSE))
#ifdef __clang__
#define MP_ROR_32(MASK, COUNT) (uint32_t)__builtin_rotateright32((MASK), (COUNT))
#define MP_ROL_32(MASK, COUNT) (uint32_t)__builtin_rotateleft32((MASK), (COUNT))
#else
#define MP_ROR_32(MASK, COUNT) (uint32_t)((MASK) << (COUNT) | ((MASK) >> (32 - (COUNT)))
#define MP_ROL_32(MASK, COUNT) (uint32_t)((MASK) >> (COUNT) | ((MASK) >> (32 - (COUNT)))
#endif
#define MP_POPCOUNT_32(MASK) __builtin_popcount((MASK))
#define MP_POPCOUNT_64(MASK) __builtin_popcountll((MASK))
#define MP_CTZ_32(MASK) __builtin_ctz((MASK))
#define MP_CTZ_64(MASK) __builtin_ctzll((MASK))
#define MP_CLZ_32(MASK) __builtin_clz((MASK))
#define MP_CLZ_64(MASK) __builtin_clzll((MASK))
#ifdef MP_DEBUG
#define MP_INLINE_ALWAYS
#define MP_INLINE_NEVER
#else
#define MP_INLINE_ALWAYS __attribute__((always_inline))
#define MP_INLINE_NEVER __attribute__((noinline))
#endif
#define MP_ASSUME(EXPRESSION) __builtin_assume((EXPRESSION))
#elif defined(_MSVC_LANG)
#define MP_MSVC
#include <intrin.h>
#if defined(_M_X64) || defined(_M_IX86)
#define MP_SPIN_WAIT _mm_pause()
#define MP_PREFETCH(PTR) _mm_prefetch((const CHAR*)(PTR), _MM_HINT_T0)
#elif defined(_M_ARM)
#define MP_SPIN_WAIT __yield()
#define MP_PREFETCH(PTR) __prefetch((const CHAR*)(PTR))
#endif
#ifndef __cplusplus
#define MP_ALIGNAS(SIZE) __declspec(align(SIZE))
#endif
#define MP_PURE
#define MP_ULTRAPURE __declspec(noalias)
#define MP_EXPECT(CONDITION, VALUE) (CONDITION)
#define MP_LIKELY_IF(CONDITION) if ((CONDITION))
#define MP_UNLIKELY_IF(CONDITION) if ((CONDITION))
#ifdef _M_ARM
#define MP_POPCOUNT_32(MASK) (uint_fast8_t)_CountOneBits((MASK))
#define MP_POPCOUNT_64(MASK) (uint_fast8_t)_CountOneBits64((MASK))
#define MP_CTZ_32(MASK) (uint_fast8_t)_CountLeadingZeros(_arm_rbit((MASK)))
#define MP_CTZ_64(MASK) (uint_fast8_t)_CountLeadingZeros64((((uint64_t)_arm_rbit((uint32_t)(MASK))) << 32) | (uint64_t)_arm_rbit(((uint32_t)(MASK)) >> 32))
#define MP_CLZ_32(MASK) (uint_fast8_t)_CountLeadingZeros((MASK))
#define MP_CLZ_64(MASK) (uint_fast8_t)_CountLeadingZeros64((MASK))
#else
#define MP_ROR_32(MASK, COUNT) (uint32_t)_rotr((MASK), (COUNT))
#define MP_ROL_32(MASK, COUNT) (uint32_t)_rotl((MASK), (COUNT))
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
#define MP_ATOMIC_TEST_ACQ(WHERE)							__atomic_load_n((mp_atomic_bool*)(WHERE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_TAS_ACQ(WHERE)							__atomic_test_and_set((mp_atomic_bool*)(WHERE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_CLEAR_REL(WHERE)							__atomic_clear((mp_atomic_bool*)(WHERE), __ATOMIC_RELEASE)
#define MP_ATOMIC_LOAD_ACQ_UPTR(WHERE)						__atomic_load_n((mp_atomic_size_t*)(WHERE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_STORE_REL_UPTR(WHERE, VALUE)				__atomic_store_n((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_SWAP_ACQ_UPTR(WHERE, VALUE)				__atomic_exchange_n((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_CAS_ACQ_UPTR(WHERE, EXPECTED, VALUE)		__atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_ATOMIC_CAS_REL_UPTR(WHERE, EXPECTED, VALUE)		__atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_FALSE, __ATOMIC_RELEASE, __ATOMIC_RELAXED)
#define MP_ATOMIC_CAS_WEAK_ACQ_UPTR(WHERE, EXPECTED, VALUE)	__atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_TRUE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_ATOMIC_CAS_WEAK_REL_UPTR(WHERE, EXPECTED, VALUE)	__atomic_compare_exchange_n((mp_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), MP_TRUE, __ATOMIC_RELEASE, __ATOMIC_RELAXED)
#define MP_ATOMIC_FAA_ACQ(WHERE, VALUE)						__atomic_fetch_add((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_ACQUIRE)
#define MP_ATOMIC_FAS_REL(WHERE, VALUE)						__atomic_fetch_sub((mp_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_BIT_SET_REL(WHERE, VALUE)					(void)__atomic_fetch_or((mp_atomic_size_t*)(WHERE), (size_t)1 << (uint_fast8_t)(VALUE), __ATOMIC_RELEASE)
#define MP_ATOMIC_ACQUIRE_FENCE								__atomic_thread_fence(__ATOMIC_ACQUIRE)
#define MP_WIDE_CAS_ACQ(WHERE, EXPECTED, VALUE)				__atomic_compare_exchange((volatile __int128*)(WHERE), (__int128*)(EXPECTED), (__int128*)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MP_WIDE_CAS_REL(WHERE, EXPECTED, VALUE)				__atomic_compare_exchange((volatile __int128*)(WHERE), (__int128*)(EXPECTED), (__int128*)(VALUE), MP_FALSE, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#elif defined(MP_MSVC)
// I'd like to give special thanks to the visual studio devteam for being more than 10 years ahead of the competition in not adding support to the C11 standard to their compiler.
#define MP_ATOMIC(TYPE) TYPE volatile
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
#define MP_ATOMIC_SWAP_ACQ_UPTR(WHERE, VALUE) MP_MSVC_ATOMIC_ACQ(_InterlockedExchange)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_CAS_ACQ_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_ACQ(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), *(const mp_msvc_size_t*)(VALUE), (mp_msvc_size_t)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_CAS_REL_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_REL(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), *(const mp_msvc_size_t*)(VALUE), (mp_msvc_size_t)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_CAS_WEAK_ACQ_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_ACQ(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), *(const mp_msvc_size_t*)(VALUE), (mp_msvc_size_t)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_CAS_WEAK_REL_UPTR(WHERE, EXPECTED, VALUE) (MP_MSVC_ATOMIC_REL(_InterlockedCompareExchange)((mp_msvc_atomic_size_t*)(WHERE), *(const mp_msvc_size_t*)(VALUE), (mp_msvc_size_t)(EXPECTED)) == *(const mp_msvc_size_t*)EXPECTED)
#define MP_ATOMIC_FAA_ACQ(WHERE, VALUE) (size_t)MP_MSVC_ATOMIC_ACQ(_InterlockedExchangeAdd)((mp_msvc_atomic_size_t*)(WHERE), (mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_FAS_REL(WHERE, VALUE) (size_t)MP_MSVC_ATOMIC_REL(_InterlockedExchangeAdd)((mp_msvc_atomic_size_t*)(WHERE), -(mp_msvc_size_t)(VALUE))
#define MP_ATOMIC_BIT_SET_REL(WHERE, VALUE) (void)MP_MSVC_ATOMIC_REL(_interlockedbittestandset)((mp_msvc_atomic_size_t*)(WHERE), (uint_fast8_t)(VALUE))
#define MP_ATOMIC_ACQUIRE_FENCE _ReadBarrier()

typedef struct mp_msvc_uintptr_pair
{
	MP_ALIGNAS(MP_DPTR_SIZE) size_t a, b;
} mp_msvc_uintptr_pair;

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

#define MP_WIDE_CAS_ACQ(WHERE, EXPECTED, VALUE) mp_impl_cmpxchg16_acq((volatile mp_msvc_uintptr_pair*)(WHERE), (const mp_msvc_uintptr_pair*)(EXPECTED), (const mp_msvc_uintptr_pair*)(VALUE))
#define MP_WIDE_CAS_REL(WHERE, EXPECTED, VALUE) mp_impl_cmpxchg16_rel((volatile mp_msvc_uintptr_pair*)(WHERE), (const mp_msvc_uintptr_pair*)(EXPECTED), (const mp_msvc_uintptr_pair*)(VALUE))
#endif
#define MP_ATOMIC_LOAD_ACQ_PTR(WHERE) (void*)MP_ATOMIC_LOAD_ACQ_UPTR((mp_atomic_size_t*)WHERE)
#define MP_ATOMIC_STORE_REL_PTR(WHERE, VALUE) MP_ATOMIC_STORE_REL_UPTR((mp_atomic_size_t*)WHERE, (size_t)VALUE)
#define MP_ATOMIC_SWAP_ACQ_PTR(WHERE, VALUE) (void*)MP_ATOMIC_SWAP_ACQ_UPTR((mp_atomic_size_t*)WHERE, (size_t)VALUE)
#define MP_ATOMIC_CAS_ACQ_PTR(WHERE, EXPECTED, VALUE) MP_ATOMIC_CAS_ACQ_UPTR((mp_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)
#define MP_ATOMIC_CAS_REL_PTR(WHERE, EXPECTED, VALUE) MP_ATOMIC_CAS_REL_UPTR((mp_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)
#define MP_ATOMIC_CAS_WEAK_ACQ_PTR(WHERE, EXPECTED, VALUE) MP_ATOMIC_CAS_WEAK_ACQ_UPTR((mp_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)
#define MP_ATOMIC_CAS_WEAK_REL_PTR(WHERE, EXPECTED, VALUE) MP_ATOMIC_CAS_WEAK_REL_UPTR((mp_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)

#define MP_NON_ATOMIC_SET(WHERE) (*((mp_bool*)&(WHERE)) = MP_TRUE)
#define MP_NON_ATOMIC_LOAD_PTR(WHERE) *((const void**)(WHERE))
#define MP_NON_ATOMIC_STORE_PTR(WHERE, VALUE) *((void**)(WHERE)) = (VALUE)
#define MP_NON_ATOMIC_LOAD_UPTR(WHERE) *((const size_t*)(WHERE))
#define MP_NON_ATOMIC_STORE_UPTR(WHERE, VALUE) *((size_t*)(WHERE)) = (VALUE)

// ================================================================
//	MPMALLOC MAIN DATA TYPES
// ================================================================

typedef MP_ATOMIC(mp_bool) mp_atomic_bool;
typedef MP_ATOMIC(size_t) mp_atomic_size_t;
typedef MP_ATOMIC(void*) mp_atomic_address;

typedef struct mp_flist_node { struct mp_flist_node* next; } mp_flist_node;
typedef MP_ATOMIC(mp_flist_node*) mp_rlist;
typedef MP_ATOMIC(size_t) mp_chunk_list;

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
	uint8_t block_size_log2;
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
	uint32_t block_size;
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
} mp_tcache;

typedef struct mp_tcache_pool_head
{
	MP_ALIGNAS(MP_DPTR_SIZE) mp_tcache* head;
	size_t generation;
} mp_tcache_pool_head;

typedef struct mp_shared_counter { MP_SHARED_ATTR mp_atomic_size_t value; } mp_shared_counter;

// ================================================================
//	SIZE CLASS MAPPING FUNCTIONS
// ================================================================

static const uint16_t MP_SIZE_MAP_0[]  = { 1 };
static const uint16_t MP_SIZE_MAP_1[]  = { 2 };
static const uint16_t MP_SIZE_MAP_2[]  = { 4 };
static const uint16_t MP_SIZE_MAP_3[]  = { 8, 12 };
static const uint16_t MP_SIZE_MAP_4[]  = { 16, 20, 24, 28 };
static const uint16_t MP_SIZE_MAP_5[]  = { 32, 40, 48, 56 };
static const uint16_t MP_SIZE_MAP_6[]  = { 64, 80, 96, 112 };
static const uint16_t MP_SIZE_MAP_7[]  = { 128, 144, 160, 176, 192, 208, 224, 240 };
static const uint16_t MP_SIZE_MAP_8[]  = { 256, 272, 288, 304, 320, 352, 384, 416, 448, 480 };
static const uint16_t MP_SIZE_MAP_9[]  = { 512, 544, 576, 640, 704, 768, 832, 896, 960 };
static const uint16_t MP_SIZE_MAP_10[] = { 1024, 1088, 1152, 1280, 1408, 1536, 1664, 1792, 1920 };
static const uint16_t MP_SIZE_MAP_11[] = { 2048, 2176, 2304, 2560, 2816, 3072, 3328, 3584, 3840 };

static const uint16_t MP_SIZE_MAP_MAX = 4096;
static const uint8_t MP_SIZE_MAP_MAX_LOG2 = 12;

static const uint16_t* const MP_SIZE_MAP[12] =
{
	MP_SIZE_MAP_0, MP_SIZE_MAP_1, MP_SIZE_MAP_2, MP_SIZE_MAP_3,
	MP_SIZE_MAP_4, MP_SIZE_MAP_5, MP_SIZE_MAP_6, MP_SIZE_MAP_7,
	MP_SIZE_MAP_8, MP_SIZE_MAP_9, MP_SIZE_MAP_10, MP_SIZE_MAP_11
};

static const uint8_t MP_SIZE_MAP_SIZES[12] =
{
	MP_ARRAY_SIZE(MP_SIZE_MAP_0), MP_ARRAY_SIZE(MP_SIZE_MAP_1), MP_ARRAY_SIZE(MP_SIZE_MAP_2), MP_ARRAY_SIZE(MP_SIZE_MAP_3),
	MP_ARRAY_SIZE(MP_SIZE_MAP_4), MP_ARRAY_SIZE(MP_SIZE_MAP_5), MP_ARRAY_SIZE(MP_SIZE_MAP_6), MP_ARRAY_SIZE(MP_SIZE_MAP_7),
	MP_ARRAY_SIZE(MP_SIZE_MAP_8), MP_ARRAY_SIZE(MP_SIZE_MAP_9), MP_ARRAY_SIZE(MP_SIZE_MAP_10), MP_ARRAY_SIZE(MP_SIZE_MAP_11)
};

static const size_t MP_SIZE_CLASS_COUNT =
	MP_ARRAY_SIZE(MP_SIZE_MAP_0) + MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_2) + MP_ARRAY_SIZE(MP_SIZE_MAP_3) +
	MP_ARRAY_SIZE(MP_SIZE_MAP_4) + MP_ARRAY_SIZE(MP_SIZE_MAP_5) + MP_ARRAY_SIZE(MP_SIZE_MAP_6) + MP_ARRAY_SIZE(MP_SIZE_MAP_7) +
	MP_ARRAY_SIZE(MP_SIZE_MAP_8) + MP_ARRAY_SIZE(MP_SIZE_MAP_9) + MP_ARRAY_SIZE(MP_SIZE_MAP_10) + MP_ARRAY_SIZE(MP_SIZE_MAP_11);

static const size_t MP_TCACHE_SMALL_BIN_BUFFER_SIZE = MP_PTR_SIZE * MP_SIZE_CLASS_COUNT;

static const uint8_t MP_SIZE_MAP_OFFSETS[12] =
{
	(uint8_t)0,
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_0)),
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_0)),
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_2) + MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_0)),
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_3) + MP_ARRAY_SIZE(MP_SIZE_MAP_2) + MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_0)),
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_4) + MP_ARRAY_SIZE(MP_SIZE_MAP_3) + MP_ARRAY_SIZE(MP_SIZE_MAP_2) + MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_0)),
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_5) + MP_ARRAY_SIZE(MP_SIZE_MAP_4) + MP_ARRAY_SIZE(MP_SIZE_MAP_3) + MP_ARRAY_SIZE(MP_SIZE_MAP_2) + MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_0)),
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_6) + MP_ARRAY_SIZE(MP_SIZE_MAP_5) + MP_ARRAY_SIZE(MP_SIZE_MAP_4) + MP_ARRAY_SIZE(MP_SIZE_MAP_3) + MP_ARRAY_SIZE(MP_SIZE_MAP_2) + MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_0)),
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_7) + MP_ARRAY_SIZE(MP_SIZE_MAP_6) + MP_ARRAY_SIZE(MP_SIZE_MAP_5) + MP_ARRAY_SIZE(MP_SIZE_MAP_4) + MP_ARRAY_SIZE(MP_SIZE_MAP_3) + MP_ARRAY_SIZE(MP_SIZE_MAP_2) + MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_0)),
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_8) + MP_ARRAY_SIZE(MP_SIZE_MAP_7) + MP_ARRAY_SIZE(MP_SIZE_MAP_6) + MP_ARRAY_SIZE(MP_SIZE_MAP_5) + MP_ARRAY_SIZE(MP_SIZE_MAP_4) + MP_ARRAY_SIZE(MP_SIZE_MAP_3) + MP_ARRAY_SIZE(MP_SIZE_MAP_2) + MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_0)),
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_9) + MP_ARRAY_SIZE(MP_SIZE_MAP_8) + MP_ARRAY_SIZE(MP_SIZE_MAP_7) + MP_ARRAY_SIZE(MP_SIZE_MAP_6) + MP_ARRAY_SIZE(MP_SIZE_MAP_5) + MP_ARRAY_SIZE(MP_SIZE_MAP_4) + MP_ARRAY_SIZE(MP_SIZE_MAP_3) + MP_ARRAY_SIZE(MP_SIZE_MAP_2) + MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_0)),
	(uint8_t)(MP_ARRAY_SIZE(MP_SIZE_MAP_10) + MP_ARRAY_SIZE(MP_SIZE_MAP_9) + MP_ARRAY_SIZE(MP_SIZE_MAP_8) + MP_ARRAY_SIZE(MP_SIZE_MAP_7) + MP_ARRAY_SIZE(MP_SIZE_MAP_6) + MP_ARRAY_SIZE(MP_SIZE_MAP_5) + MP_ARRAY_SIZE(MP_SIZE_MAP_4) + MP_ARRAY_SIZE(MP_SIZE_MAP_3) + MP_ARRAY_SIZE(MP_SIZE_MAP_2) + MP_ARRAY_SIZE(MP_SIZE_MAP_1) + MP_ARRAY_SIZE(MP_SIZE_MAP_0))
};

#define MP_SIZE_MAP_SIZE 12

#ifdef MP_WINDOWS
static void* min_chunk;
static void* max_address;
#endif
static size_t expected_concurrency;
static size_t page_size;
static size_t chunk_size;
static size_t chunk_size_mask;
static size_t tcache_large_bin_buffer_size;
static size_t tcache_buffer_size;
static uint8_t page_size_log2;
static uint8_t chunk_size_log2;
#ifdef MP_64BIT
static bool mp_init_flag;
#endif
#ifdef MP_DEBUG
static mp_debugger_options debugger;
static bool mp_debugger_enabled_flag;
#endif

MP_INLINE_ALWAYS static void mp_sys_init()
{
#ifdef MP_WINDOWS
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	page_size = info.dwPageSize;
	chunk_size = page_size * MP_CACHE_LINE_SIZE * 8;
	max_address = info.lpMaximumApplicationAddress;
	min_chunk = (void*)MP_ALIGN_CEIL((size_t)info.lpMinimumApplicationAddress, chunk_size);
	expected_concurrency = info.dwNumberOfProcessors;
#else
	page_size = (size_t)getpagesize();
	chunk_size = page_size * MP_CACHE_LINE_SIZE * 8;
#endif
	chunk_size_mask = chunk_size - 1;
	page_size_log2 = MP_FLOOR_LOG2(page_size);
	chunk_size_log2 = MP_FLOOR_LOG2(chunk_size);
	MP_INVARIANT(page_size >= 4096);
	MP_INVARIANT(chunk_size >= (32 * 4096));
	tcache_large_bin_buffer_size = MP_PTR_SIZE * ((size_t)chunk_size_log2 - page_size_log2);
	tcache_buffer_size = (MP_TCACHE_SMALL_BIN_BUFFER_SIZE + tcache_large_bin_buffer_size) * 2;
}

// ================================================================
//	MISCELLANEOUS
// ================================================================

MP_INLINE_ALWAYS static void mp_lazy_zero_fill(void* ptr, size_t size)
{
#if MP_CACHE_LINE_SIZE
#endif
}

// ================================================================
//	DEBUG FUNCTIONS
// ================================================================

#ifdef MP_DEBUG
#include <stdio.h>
static void mp_default_debugger_message_callback(void* context, const char* message, size_t size)
{
	MP_INVARIANT(message != NULL);
	(void)fwrite(message, 1, size, stdout);
}

static void mp_default_debugger_warning_callback(void* context, const char* message, size_t size)
{
	MP_INVARIANT(message != NULL);
	(void)fwrite(message, 1, size, stdout);
}

static void mp_default_debugger_error_callback(void* context, const char* message, size_t size)
{
	MP_INVARIANT(message != NULL);
	(void)fwrite(message, 1, size, stderr);
}
#endif

MP_INLINE_ALWAYS static void mp_init_redzone(void* buffer, size_t size)
{
#ifdef MP_CHECK_OVERFLOW
	buffer = (uint8_t*)buffer + size;
	(void)memset(buffer, MP_REDZONE_VALUE, MP_REDZONE_SIZE);
#endif
}

MP_INLINE_ALWAYS static mp_bool mp_check_redzone(const void* buffer, size_t size)
{
#ifdef MP_CHECK_OVERFLOW
	const size_t* ptr;
	size_t expected, i;
	const size_t count = MP_REDZONE_SIZE >> MP_PTR_SIZE_LOG2;
	buffer = (const uint8_t*)buffer + size;
	ptr = (const size_t*)buffer;
	(void)memset(&expected, MP_REDZONE_VALUE, MP_PTR_SIZE);
	for (i = 0; i != count; ++i)
		MP_UNLIKELY_IF(ptr[i] != expected)
		return MP_FALSE;
#endif
	return MP_TRUE;
}

// ================================================================
//	OS / BACKEND FUNCTIONS
// ================================================================

#ifdef MP_WINDOWS
typedef DWORD mp_thread_id;
typedef PVOID(WINAPI* VirtualAlloc2_t)(HANDLE Process, PVOID BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG PageProtection, MEM_EXTENDED_PARAMETER* ExtendedParameters, ULONG ParameterCount);

static HANDLE process_handle;
static VirtualAlloc2_t virtualalloc2;
static MEM_ADDRESS_REQUIREMENTS va2_addr_req;
static MEM_EXTENDED_PARAMETER va2_ext_param;

MP_INLINE_ALWAYS static void mp_os_init()
{
	HMODULE m;
	process_handle = GetCurrentProcess();
	m = GetModuleHandle(TEXT("KernelBase.DLL"));
	MP_INVARIANT(m != NULL);
	virtualalloc2 = (VirtualAlloc2_t)GetProcAddress(m, "VirtualAlloc2");
	MP_INVARIANT(virtualalloc2 != NULL);
	va2_addr_req.Alignment = chunk_size;
	va2_addr_req.HighestEndingAddress = max_address;
	va2_addr_req.LowestStartingAddress = min_chunk;
	va2_ext_param.Type = MemExtendedParameterAddressRequirements;
	va2_ext_param.Pointer = &va2_addr_req;
}

MP_INLINE_ALWAYS static void* mp_os_malloc(size_t size)
{
	return virtualalloc2(process_handle, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &va2_ext_param, 1);
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

#elif defined(MP_LINUX)

typedef pthread_t mp_thread_id;

MP_INLINE_ALWAYS static void mp_os_init() { }

MP_INLINE_ALWAYS static void* mp_os_malloc(size_t size)
{
	uint8_t* tmp = mmap(NULL, size * 2, PROT_READ | PROT_WRITE, MAP_ANON | MAP_UNINITIALIZED, -1, 0);
	uint8_t* tmp_limit = base + chunk_size * 2;
	uint8_t* r = (uint8_t*)MP_ALIGN_FLOOR((size_t)tmp, chunk_size);
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

typedef MP_ATOMIC(mp_thread_id) mp_atomic_thread_id;

static void mp_empty_function() { }

static mp_fn_init		backend_init	= mp_os_init;
static mp_fn_cleanup	backend_cleanup	= mp_empty_function;
static mp_fn_malloc		backend_malloc	= mp_os_malloc;
static mp_fn_resize		backend_resize	= mp_os_resize;
static mp_fn_free		backend_free	= mp_os_free;
static mp_fn_purge		backend_purge	= mp_os_purge;

// ================================================================
//	RANDOM
// ================================================================

typedef uint32_t mp_romu_mono32;

#define MP_ROMU_MONO32_INIT(SEED) (((SEED) & 0x1fffffffu) + 1156979152u)

MP_INLINE_ALWAYS static uint_fast16_t mp_romu_mono32_get(mp_romu_mono32* state)
{
	uint_fast16_t r = (uint_fast16_t)(*state & 0xffff);
	*state *= 3611795771U;
	*state = MP_ROL_32(*state, 12);
	return r;
}

// ================================================================
//	LOCK-FREE CHUNK FREE LIST
// ================================================================

MP_INLINE_ALWAYS static void mp_chunk_list_push(mp_chunk_list*head, void* ptr)
{
	mp_flist_node* new_head;
	size_t prior, desired;
	new_head = (mp_flist_node*)ptr;
	MP_SPIN_LOOP
	{
		prior = MP_ATOMIC_LOAD_ACQ_UPTR(head);
		new_head->next = (mp_flist_node*)(prior & ~chunk_size_mask);
		desired = (size_t)new_head | (((prior & chunk_size_mask) + 1) & chunk_size_mask);
		MP_LIKELY_IF(MP_ATOMIC_CAS_WEAK_REL_UPTR(head, &prior, desired))
			break;
	}
}

MP_INLINE_ALWAYS static void* mp_chunk_list_pop(mp_chunk_list* head)
{
	mp_flist_node* ptr;
	size_t prior, desired;
	MP_SPIN_LOOP
	{
		prior = MP_ATOMIC_LOAD_ACQ_UPTR(head);
		ptr = (mp_flist_node*)(prior & ~chunk_size_mask);
		MP_UNLIKELY_IF(ptr == NULL)
			return NULL;
		desired = (size_t)ptr->next | (((prior & chunk_size_mask) + 1) & chunk_size_mask);
		MP_LIKELY_IF(MP_ATOMIC_CAS_WEAK_ACQ_UPTR(head, &prior, desired))
			return ptr;
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
		return mp_lcache_malloc(MP_ALIGN_CEIL(size, chunk_size), MP_ENABLE_FALLBACK);
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
		MP_LIKELY_IF(MP_ATOMIC_CAS_WEAK_ACQ_PTR(allocator, &prior, n))
			return r;
	}
}

MP_ATTR void MP_CALL mp_persistent_cleanup_impl(mp_persistent_allocator* allocator)
{
	mp_persistent_node* next;
	mp_persistent_node* n;
	for (n = (mp_persistent_node*)MP_ATOMIC_SWAP_ACQ_PTR(allocator, NULL); n != NULL; n = next)
	{
		next = n->next;
		backend_free(n, chunk_size);
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
		MP_PREFETCH(prior.head);
		desired.head = prior.head->next;
		desired.generation = prior.generation + 1;
		MP_LIKELY_IF(MP_WIDE_CAS_ACQ(&tcache_freelist, &prior, &desired))
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
	(void)memset(buffer, 0, k);
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
		MP_LIKELY_IF(MP_WIDE_CAS_REL(&tcache_freelist, &prior, &desired))
			break;
	}
}

// ================================================================
//	BLOCK ALLOCATOR
// ================================================================

MP_ULTRAPURE MP_INLINE_ALWAYS static size_t mp_chunk_size_of_small(size_t size)
{
	MP_INVARIANT(size != 0);
	size *= MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY;
	return MP_CEIL_POW2(size);
}

MP_ULTRAPURE MP_INLINE_ALWAYS static size_t mp_chunk_size_of_large(size_t size)
{
	MP_INVARIANT(size != 0);
	size *= MP_BLOCK_ALLOCATOR_MAX_CAPACITY;
	MP_UNLIKELY_IF(size > chunk_size)
		return chunk_size;
	return MP_CEIL_POW2(size);
}

MP_PURE MP_INLINE_ALWAYS static mp_bool mp_is_valid_block_allocator(mp_block_allocator* allocator)
{
	return
		allocator->owner != NULL && allocator->buffer != NULL &&
		allocator->free_count < MP_BLOCK_ALLOCATOR_MAX_CAPACITY &&
		allocator->block_size_log2 != 0 && allocator->size_class < (chunk_size_log2 - page_size_log2) &&
		(uint8_t)allocator->linked < 2;
}

MP_PURE MP_INLINE_ALWAYS static mp_bool mp_is_valid_block_allocator_intrusive(mp_block_allocator_intrusive* allocator)
{
	return
		allocator->owner != NULL && allocator->free_count < MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY &&
		allocator->block_size != 0 && allocator->size_class < MP_SIZE_CLASS_COUNT &&
		(uint8_t)allocator->linked < 2;
}

MP_PURE MP_INLINE_ALWAYS static uint_fast32_t mp_block_allocator_index_of(mp_block_allocator* allocator, void* ptr)
{
	MP_INVARIANT(mp_is_valid_block_allocator(allocator));
	return (uint_fast32_t)(((size_t)((uint8_t*)ptr - (uint8_t*)allocator->buffer)) >> allocator->block_size_log2);
}

MP_PURE MP_INLINE_ALWAYS static uint_fast32_t mp_block_allocator_intrusive_index_of(mp_block_allocator_intrusive* allocator, void* ptr)
{
	MP_INVARIANT(mp_is_valid_block_allocator_intrusive(allocator));
	return (uint_fast32_t)(((size_t)((uint8_t*)ptr - (uint8_t*)allocator)) / allocator->block_size);
}

MP_PURE MP_INLINE_ALWAYS static mp_bool mp_block_allocator_owns(mp_block_allocator* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_is_valid_block_allocator(allocator));
	MP_UNLIKELY_IF((uint8_t*)ptr < (uint8_t*)allocator->buffer)
		return MP_FALSE;
	MP_UNLIKELY_IF((uint8_t*)ptr >= (uint8_t*)allocator->buffer + mp_chunk_size_of_large((size_t)1 << allocator->block_size_log2))
		return MP_FALSE;
	index = mp_block_allocator_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_SIZE_LOG2;
	bit_index = index & MP_PTR_SIZE_MASK;
	return !MP_BT(allocator->free_map[mask_index], bit_index);
}

MP_PURE MP_INLINE_ALWAYS static mp_bool mp_block_allocator_intrusive_owns(mp_block_allocator_intrusive* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_is_valid_block_allocator_intrusive(allocator));
	MP_UNLIKELY_IF((uint8_t*)ptr < (uint8_t*)allocator)
		return MP_FALSE;
	MP_UNLIKELY_IF((uint8_t*)ptr >= (uint8_t*)allocator + mp_chunk_size_of_small(allocator->block_size))
		return MP_FALSE;
	index = mp_block_allocator_intrusive_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_SIZE_LOG2;
	bit_index = index & MP_PTR_SIZE_MASK;
	return !MP_BT(allocator->free_map[mask_index], bit_index);
}

MP_INLINE_ALWAYS static void mp_block_allocator_init(mp_block_allocator* allocator, uint_fast8_t block_size_log2, uint_fast8_t sc, size_t chunk_size, struct mp_tcache* owner, void* buffer)
{
	uint_fast32_t mask_count, bit_count;
	MP_INVARIANT(chunk_size_log2 > block_size_log2);
	MP_INVARIANT(allocator != NULL);
	MP_INVARIANT(buffer != NULL);
	allocator->next = NULL;
	allocator->free_count = 1U << (chunk_size_log2 - block_size_log2);
	allocator->block_size_log2 = block_size_log2;
	allocator->size_class = sc;
	allocator->owner = owner;
	allocator->buffer = (uint8_t*)buffer;
	MP_NON_ATOMIC_SET(allocator->linked);
	(void)memset(allocator->free_map, 0, MP_CACHE_LINE_SIZE / 2);
	mask_count = allocator->free_count >> MP_PTR_SIZE_LOG2;
	bit_count = allocator->free_count & MP_PTR_SIZE_MASK;
	(void)memset(allocator->free_map, 0xff, mask_count * MP_PTR_SIZE);
	allocator->free_map[mask_count] |= ((size_t)1 << bit_count) - (size_t)1;
	(void)memset((void*)allocator->marked_map, 0, MP_CACHE_LINE_SIZE / 2);
}

MP_INLINE_ALWAYS static void mp_block_allocator_intrusive_init(mp_block_allocator_intrusive* allocator, uint_fast32_t block_size, uint_fast8_t sc, size_t chunk_size, struct mp_tcache* owner)
{
	uint_fast32_t reserved_count, capacity, mask_count, bit_count;
	MP_INVARIANT(allocator != NULL);
	allocator->next = NULL;
	capacity = (uint_fast32_t)(chunk_size / block_size);
	reserved_count = (sizeof(mp_block_allocator_intrusive) + block_size - 1) / block_size;
	MP_INVARIANT(reserved_count >= 1);
	MP_INVARIANT(reserved_count < capacity);
	capacity -= reserved_count;
	MP_UNLIKELY_IF(capacity > MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY)
		capacity = MP_BLOCK_ALLOCATOR_INTRUSIVE_MAX_CAPACITY - reserved_count;
	allocator->free_count = capacity;
	allocator->block_size = block_size;
	allocator->size_class = sc;
	allocator->owner = owner;
	MP_NON_ATOMIC_SET(allocator->linked);
	(void)memset(allocator->free_map, 0xff, MP_CACHE_LINE_SIZE);
	(void)memset((void*)allocator->marked_map, 0, MP_CACHE_LINE_SIZE);
	mask_count = reserved_count >> MP_PTR_SIZE_LOG2;
	bit_count = reserved_count & MP_PTR_SIZE_MASK;
	(void)memset(allocator->free_map, 0, mask_count);
	allocator->free_map[mask_count] &= ~(((size_t)1 << bit_count) - (size_t)1);
}

MP_INLINE_NEVER static uint_fast32_t mp_block_allocator_reclaim(size_t* free_map, mp_atomic_size_t* marked_map, uint_fast32_t bitmask_count)
{
	size_t mask;
	uint_fast32_t i, freed_count;
	freed_count = 0;
	for (i = 0; i != bitmask_count; ++i)
	{
		MP_UNLIKELY_IF(MP_ATOMIC_LOAD_ACQ_UPTR(marked_map + i) == 0)
			continue;
		mask = MP_ATOMIC_SWAP_ACQ_UPTR(marked_map + i, 0);
		freed_count += MP_POPCOUNT(mask);
		free_map[i] |= mask;
	}
	return freed_count;
}

MP_INLINE_ALWAYS static void* mp_block_allocator_malloc(mp_block_allocator* allocator)
{
	uint_fast32_t mask_index, bit_index, offset;
	MP_INVARIANT(allocator->linked != 0);
	MP_INVARIANT(allocator->free_count != 0);
	for (mask_index = 0; mask_index != MP_BLOCK_ALLOCATOR_MASK_COUNT; ++mask_index)
	{
		MP_UNLIKELY_IF(allocator->free_map[mask_index] == 0)
			continue;
		bit_index = MP_CTZ(allocator->free_map[mask_index]);
		MP_BR(allocator->free_map[mask_index], bit_index);
		offset = (mask_index << MP_PTR_SIZE_LOG2) | bit_index;
		offset <<= allocator->block_size_log2;
		--allocator->free_count;
		MP_UNLIKELY_IF(allocator->free_count == 0)
			allocator->free_count += mp_block_allocator_reclaim(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_MASK_COUNT);
		return allocator->buffer + offset;
	}
	MP_UNREACHABLE;
}

MP_INLINE_ALWAYS static void* mp_block_allocator_intrusive_malloc(mp_block_allocator_intrusive* allocator)
{
	uint_fast32_t mask_index, bit_index, offset;
	MP_INVARIANT(allocator->linked != 0);
	MP_INVARIANT(allocator->free_count != 0);
	for (mask_index = 0; mask_index != MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT; ++mask_index)
	{
		MP_UNLIKELY_IF(allocator->free_map[mask_index] == 0)
			continue;
		bit_index = MP_CTZ(allocator->free_map[mask_index]);
		MP_BR(allocator->free_map[mask_index], bit_index);
		offset = (mask_index << MP_PTR_SIZE_LOG2) | bit_index;
		offset *= allocator->block_size;
		--allocator->free_count;
		MP_UNLIKELY_IF(allocator->free_count == 0)
			allocator->free_count += mp_block_allocator_reclaim(allocator->free_map, allocator->marked_map, MP_BLOCK_ALLOCATOR_INTRUSIVE_MASK_COUNT);
		return (uint8_t*)allocator + offset;
	}
	MP_UNREACHABLE;
}

MP_INLINE_NEVER static void mp_block_allocator_recover(mp_atomic_bool* linked, mp_rlist* recovered, void* allocator)
{
	mp_flist_node* desired;
	desired = (mp_flist_node*)allocator;
	MP_SPIN_LOOP
	{
		MP_UNLIKELY_IF(MP_ATOMIC_TAS_ACQ(linked))
			break;
		desired->next = (mp_flist_node*)MP_ATOMIC_LOAD_ACQ_PTR(recovered);
		MP_LIKELY_IF(MP_ATOMIC_CAS_WEAK_REL_PTR(recovered, &desired->next, desired)) // Potential ABA issue
			break;
	}
}

MP_INLINE_ALWAYS static void mp_block_allocator_intrusive_free(mp_block_allocator_intrusive* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_block_allocator_intrusive_owns(allocator, ptr));
	++allocator->free_count;
	index = mp_block_allocator_intrusive_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_SIZE_LOG2;
	bit_index = index & MP_PTR_SIZE_MASK;
	MP_BS(allocator->free_map[mask_index], bit_index);
	MP_UNLIKELY_IF(!MP_ATOMIC_TEST_ACQ(&allocator->linked))
		mp_block_allocator_recover(&allocator->linked, allocator->owner->recovered + allocator->size_class, allocator);
}

MP_INLINE_ALWAYS static void mp_block_allocator_intrusive_free_shared(mp_block_allocator_intrusive* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_block_allocator_intrusive_owns(allocator, ptr));
	index = mp_block_allocator_intrusive_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_SIZE_LOG2;
	bit_index = index & MP_PTR_SIZE_MASK;
	MP_ATOMIC_BIT_SET_REL(allocator->marked_map + mask_index, bit_index);
	MP_UNLIKELY_IF(!MP_ATOMIC_TEST_ACQ(&allocator->linked))
		mp_block_allocator_recover(&allocator->linked, allocator->owner->recovered + allocator->size_class, allocator);
}

MP_INLINE_ALWAYS static void mp_block_allocator_free(mp_block_allocator* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_block_allocator_owns(allocator, ptr));
	++allocator->free_count;
	index = mp_block_allocator_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_SIZE_LOG2;
	bit_index = index & MP_PTR_SIZE_MASK;
	MP_BS(allocator->free_map[mask_index], bit_index);
	MP_UNLIKELY_IF(!MP_ATOMIC_TEST_ACQ(&allocator->linked))
		mp_block_allocator_recover(&allocator->linked, allocator->owner->recovered_large + allocator->size_class, allocator);
}

MP_INLINE_ALWAYS static void mp_block_allocator_free_shared(mp_block_allocator* allocator, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	MP_INVARIANT(mp_block_allocator_owns(allocator, ptr));
	index = mp_block_allocator_index_of(allocator, ptr);
	mask_index = index >> MP_PTR_SIZE_LOG2;
	bit_index = index & MP_PTR_SIZE_MASK;
	MP_ATOMIC_BIT_SET_REL(allocator->marked_map + mask_index, bit_index);
	MP_UNLIKELY_IF(!MP_ATOMIC_TEST_ACQ(&allocator->linked))
		mp_block_allocator_recover(&allocator->linked, allocator->owner->recovered_large + allocator->size_class, allocator);
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
		MP_LIKELY_IF(MP_ATOMIC_CAS_REL_PTR(root, &branch, new_branch))
		{
			branch = new_branch;
			(void)memset((void*)branch, 0, real_branch_size);
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
		MP_LIKELY_IF(MP_ATOMIC_CAS_REL_PTR(branch, &leaf, new_leaf))
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
	(void)memset((void*)lcache_bins, 0, k);
	MP_INVARIANT(lcache_bins != NULL);
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

MP_TLS static mp_tcache* this_thread_tcache;

MP_INLINE_ALWAYS static mp_block_allocator* mp_tcache_find_allocator(void* buffer)
{
	size_t id;
	id = (size_t)buffer >> chunk_size_log2;
#ifdef MP_32BIT
	MP_INVARIANT(tcache_lookup != NULL);
	return tcache_lookup + id;
#else
	return (mp_block_allocator*)mp_trie_find(lcache_bin_roots, id, MP_FLOOR_LOG2(sizeof(mp_block_allocator)));
#endif
}

MP_INLINE_ALWAYS static mp_block_allocator* mp_tcache_insert_allocator(void* buffer)
{
#ifdef MP_32BIT
	return mp_tcache_find_allocator(buffer);
#else
	size_t id, object_size;
	uint_fast8_t object_size_log2;
	id = (size_t)buffer >> chunk_size_log2;
	object_size = sizeof(mp_block_allocator);
	object_size_log2 = MP_FLOOR_LOG2(object_size);
	return (mp_block_allocator*)mp_trie_insert(lcache_bin_roots, id, object_size_log2);
#endif
}

MP_INLINE_ALWAYS static mp_block_allocator* mp_tcache_block_allocator_of(const void* ptr)
{
	size_t mask = (size_t)ptr;
	mask &= ~chunk_size_mask;
	return mp_tcache_find_allocator((void*)mask);
}

MP_PURE MP_INLINE_ALWAYS static uint_fast8_t mp_tcache_size_class_small(size_t size)
{
	uint_fast8_t log2, i;
	log2 = MP_FLOOR_LOG2(size);
	for (i = 0; i != MP_SIZE_MAP_SIZES[log2]; ++i)
		MP_LIKELY_IF(MP_SIZE_MAP[log2][i] >= size)
			return MP_SIZE_MAP_OFFSETS[log2] + i;
	return MP_CEIL_LOG2(size) - MP_SIZE_MAP_MAX_LOG2;
}

MP_PURE MP_INLINE_ALWAYS static uint_fast32_t mp_tcache_size_class_large(size_t size)
{
	return MP_CEIL_LOG2(size) - page_size_log2;
}

MP_INLINE_NEVER static void* mp_tcache_malloc_small_slow(mp_tcache* tcache, size_t size, uint_fast8_t sc)
{
	void* r;
	size_t k;
	mp_block_allocator_intrusive* allocator;
	mp_block_allocator_intrusive** bin;
	bin = tcache->bins + sc;
	MP_INVARIANT(this_thread_tcache != NULL);
	k = mp_chunk_size_of_small(size);
	allocator = (mp_block_allocator_intrusive*)mp_malloc(k);
	MP_UNLIKELY_IF(allocator == NULL)
		return NULL;
	mp_block_allocator_intrusive_init(allocator, (uint_fast32_t)size, sc, k, this_thread_tcache);
	r = mp_block_allocator_intrusive_malloc(allocator);
	allocator->next = *bin;
	*bin = allocator;
	return r;
}

MP_INLINE_NEVER static void* mp_tcache_malloc_large_slow(mp_tcache* tcache, size_t size, uint_fast8_t sc)
{
	void* r;
	void* buffer;
	size_t k;
	mp_block_allocator* allocator;
	mp_block_allocator** bin;
	MP_INVARIANT(this_thread_tcache != NULL);
	k = mp_chunk_size_of_large(size);
	buffer = mp_lcache_malloc(chunk_size, MP_ENABLE_FALLBACK);
	MP_UNLIKELY_IF(buffer == NULL)
		return NULL;
	allocator = mp_tcache_insert_allocator(buffer);
	MP_UNLIKELY_IF(allocator == NULL)
		return NULL;
	mp_block_allocator_init(allocator, MP_FLOOR_LOG2(size), sc, k, this_thread_tcache, buffer);
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
	mp_rlist* recover_list;
	mp_block_allocator_intrusive* allocator;
	uint_fast8_t sc;
	sc = mp_tcache_size_class_small(size);
	MP_INVARIANT(sc < MP_SIZE_CLASS_COUNT);
	bin = tcache->bins + sc;
	recover_list = tcache->recovered + sc;
	allocator = *bin;
	MP_UNLIKELY_IF(allocator == NULL && MP_ATOMIC_LOAD_ACQ_PTR(recover_list) != NULL)
		allocator = (mp_block_allocator_intrusive*)MP_ATOMIC_SWAP_ACQ_PTR(recover_list, NULL);
	MP_UNLIKELY_IF(allocator == NULL)
		return (flags & MP_ENABLE_FALLBACK) ? mp_tcache_malloc_small_slow(tcache, size, sc) : NULL;
	*bin = allocator;
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
	mp_rlist* recover_list;
	mp_block_allocator* allocator;
	uint_fast8_t sc;
	sc = mp_tcache_size_class_large(size);
	MP_INVARIANT(sc < chunk_size_log2 - page_size_log2);
	MP_INVARIANT(size == ((size_t)1 << (sc + page_size_log2)));
	bin = tcache->bins_large + sc;
	recover_list = tcache->recovered_large + sc;
	allocator = *bin;
	MP_UNLIKELY_IF(allocator == NULL && MP_ATOMIC_LOAD_ACQ_PTR(recover_list) != NULL)
		allocator = (mp_block_allocator*)MP_ATOMIC_SWAP_ACQ_PTR(recover_list, NULL);
	MP_UNLIKELY_IF(allocator == NULL)
		return (flags & MP_ENABLE_FALLBACK) ? mp_tcache_malloc_large_slow(tcache, size, sc) : NULL;
	*bin = allocator;
	r = mp_block_allocator_malloc(allocator);
	MP_INVARIANT(r != NULL);
	MP_UNLIKELY_IF(allocator->free_count == 0)
	{
		MP_ATOMIC_CLEAR_REL(&allocator->linked);
		*bin = (*bin)->next;
	}
	return r;
}

MP_INLINE_ALWAYS static void mp_tcache_check_integrity(mp_tcache* tcache)
{
#ifdef MP_DEBUG
	mp_block_allocator_intrusive* intrusive_allocator;
	mp_block_allocator* allocator;
	size_t i;
	for (i = 0; i != MP_SIZE_CLASS_COUNT; ++i)
		for (intrusive_allocator = tcache->bins[i]; intrusive_allocator != NULL; intrusive_allocator = intrusive_allocator->next)
			MP_INVARIANT(mp_is_valid_block_allocator_intrusive(intrusive_allocator));
	for (i = 0; i != chunk_size_log2 - page_size_log2; ++i)
		for (allocator = tcache->bins_large[i]; allocator != NULL; allocator = allocator->next)
			MP_INVARIANT(mp_is_valid_block_allocator(allocator));
#endif
}

// ================================================================
//	MAIN API
// ================================================================

MP_EXTERN_C_BEGIN
MP_ATTR void MP_CALL mp_init_info_default(mp_init_options* out_options)
{
	out_options->expected_concurrency = 0;
	out_options->backend = NULL;
}

MP_ATTR void MP_CALL mp_trim_options_default(mp_trim_options* out_options)
{
	out_options->trim_limit = UINTPTR_MAX;
}

MP_ATTR void MP_CALL mp_debugger_options_default(mp_debugger_options* out_options)
{
	out_options->context = NULL;
#ifdef MP_DEBUG
	out_options->message = mp_default_debugger_message_callback;
	out_options->warning = mp_default_debugger_warning_callback;
	out_options->error = mp_default_debugger_error_callback;
#endif
}

MP_ATTR size_t MP_CALL mp_backend_required_alignment()
{
	return chunk_size;
}

MP_ATTR void MP_CALL mp_init(const mp_init_options* options)
{
	mp_sys_init();
	MP_UNLIKELY_IF(options != NULL)
	{
		expected_concurrency = options->expected_concurrency;
		MP_INVARIANT(expected_concurrency < chunk_size);
		MP_UNLIKELY_IF(options->backend != NULL)
		{
			backend_init = options->backend->init;
			backend_cleanup = options->backend->cleanup;
			backend_malloc = options->backend->malloc;
			backend_resize = options->backend->resize;
			backend_free = options->backend->free;
			backend_purge = options->backend->purge;
		}
}	
	backend_init();
	mp_lcache_init();
#ifdef MP_32BIT
	mp_tcache_lookup_init();
#else
	mp_init_flag = MP_TRUE;
#endif
}

MP_ATTR mp_bool MP_CALL mp_is_initialized()
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
	mp_debugger_enabled_flag = MP_FALSE;
#endif
#ifdef MP_64BIT
	mp_init_flag = MP_FALSE;
#endif
}

MP_ATTR void MP_CALL mp_thread_init()
{
	MP_INVARIANT(this_thread_tcache == NULL);
	this_thread_tcache = mp_tcache_acquire();
}

MP_ATTR void MP_CALL mp_thread_cleanup()
{
	MP_INVARIANT(this_thread_tcache != NULL);
	mp_tcache_release(this_thread_tcache);
	this_thread_tcache = NULL;
}

MP_ATTR void MP_CALL mp_stats(mp_mem_stats* out_stats)
{
	MP_INVARIANT(out_stats != NULL);
}

MP_ATTR void MP_CALL mp_params(mp_global_params* out_params)
{
	MP_INVARIANT(out_params != NULL);
	out_params->page_size = page_size;
	out_params->chunk_size = chunk_size;
	out_params->expected_concurrency = expected_concurrency;
}

MP_ATTR void* MP_CALL mp_malloc(size_t size)
{
	void* r;
	size_t k;
	k = mp_round_size(MP_SIZE_WITH_REDZONE(size));
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
	return mp_round_size(MP_SIZE_WITH_REDZONE(old_size)) == mp_round_size(MP_SIZE_WITH_REDZONE(new_size));
}

MP_ATTR void* MP_CALL mp_realloc(void* ptr, size_t old_size, size_t new_size)
{
	void* r;
	MP_INVARIANT(ptr != NULL);
	MP_INVARIANT(mp_check_redzone(ptr, old_size));
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
	MP_INVARIANT(mp_check_redzone(ptr, size));
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

MP_ATTR size_t MP_CALL mp_purge(mp_flags flags, void* param)
{
	return 0;
}

MP_ATTR size_t MP_CALL mp_trim(const mp_trim_options* options)
{
	return 0;
}

MP_ATTR void* MP_CALL mp_tcache_malloc(size_t size, mp_flags flags)
{
	void* r;
	size_t k;
	MP_INVARIANT(this_thread_tcache != NULL);
	mp_tcache_check_integrity(this_thread_tcache);
	k = mp_round_size(size);
	if (size <= page_size)
		r = mp_tcache_malloc_small_fast(this_thread_tcache, k, flags);
	else
		r = mp_tcache_malloc_large_fast(this_thread_tcache, k, flags);
	mp_tcache_check_integrity(this_thread_tcache);
	MP_DEBUG_JUNK_FILL(r, size);
	return r;
}

MP_ATTR void MP_CALL mp_tcache_free(void* ptr, size_t size)
{
	mp_block_allocator_intrusive* intrusive_allocator;
	mp_block_allocator* allocator;
	size_t k;
	mp_tcache_check_integrity(this_thread_tcache);
	size = mp_round_size(size);
	MP_LIKELY_IF(size <= page_size)
	{
		k = mp_chunk_size_of_small(size);
		intrusive_allocator = mp_tcache_block_allocator_intrusive_allocator_of(ptr, k);
		MP_INVARIANT(intrusive_allocator != NULL);
		MP_LIKELY_IF(intrusive_allocator->owner == this_thread_tcache)
			mp_block_allocator_intrusive_free(intrusive_allocator, ptr);
		else
			mp_block_allocator_intrusive_free_shared(intrusive_allocator, ptr);
	}
	else
	{
		allocator = mp_tcache_block_allocator_of(ptr);
		MP_INVARIANT(allocator != NULL);
		MP_LIKELY_IF(allocator->owner == this_thread_tcache)
			mp_block_allocator_free(allocator, ptr);
		else
			mp_block_allocator_free_shared(allocator, ptr);
	}
	mp_tcache_check_integrity(this_thread_tcache);
}

MP_ATTR size_t MP_CALL mp_tcache_round_size(size_t size)
{
	uint_fast8_t log2, i;
	MP_INVARIANT(size <= chunk_size / 2);
	log2 = MP_FLOOR_LOG2(size);
	for (i = 0; i < MP_SIZE_MAP_SIZES[log2]; ++i)
		MP_LIKELY_IF(MP_SIZE_MAP[log2][i] >= size)
			return MP_SIZE_MAP[log2][i];
	return MP_CEIL_POW2(size);
}

MP_ATTR size_t MP_CALL mp_tcache_flush(mp_flags flags, void* param)
{
	return 0;
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

MP_ATTR void MP_CALL mp_lcache_free(void* ptr, size_t size)
{
	mp_chunk_list* bin;
	bin = mp_lcache_insert_bin(size);
	MP_INVARIANT(bin != NULL);
	mp_chunk_list_push(bin, ptr);
}

MP_ATTR size_t MP_CALL mp_lcache_round_size(size_t size)
{
	return MP_ALIGN_CEIL(size, chunk_size);
}

MP_ATTR size_t MP_CALL mp_lcache_flush(mp_flags flags, void* param)
{
	return 0;
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
	MP_INVARIANT(backend_malloc != NULL);
	k = mp_round_size(MP_SIZE_WITH_REDZONE(size));
	r = backend_malloc(k);
	MP_DEBUG_JUNK_FILL(r, size);
	mp_init_redzone(r, size);
	return r;
}

MP_ATTR mp_bool MP_CALL mp_backend_resize(void* ptr, size_t old_size, size_t new_size)
{
	size_t k;
	MP_INVARIANT(backend_resize != NULL);
	mp_check_redzone(ptr, old_size);
	k = mp_round_size(MP_SIZE_WITH_REDZONE(new_size));
	MP_UNLIKELY_IF(backend_resize(ptr, old_size, k))
		return MP_FALSE;
	mp_init_redzone(ptr, new_size);
	MP_DEBUG_JUNK_FILL((uint8_t*)ptr + old_size, new_size - old_size);
	return MP_TRUE;
}

MP_ATTR void MP_CALL mp_backend_free(void* ptr, size_t size)
{
	MP_INVARIANT(backend_free != NULL);
	backend_free(ptr, size);
}

MP_ATTR void MP_CALL mp_backend_purge(void* ptr, size_t size)
{
	MP_INVARIANT(backend_purge != NULL);
	backend_purge(ptr, size);
}

MP_ATTR void MP_CALL mp_debug_init(const mp_debugger_options* options)
{
#ifdef MP_DEBUG
	(void)memcpy(&debugger, options, sizeof(mp_debugger_options));
	mp_debugger_enabled_flag = MP_TRUE;
#endif
}

MP_ATTR mp_bool MP_CALL mp_debug_enabled()
{
#ifdef MP_DEBUG
	return mp_debugger_enabled_flag;
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
		allocator = mp_tcache_block_allocator_of(ptr);
		MP_UNLIKELY_IF(allocator == NULL)
			return MP_FALSE;
		return mp_is_valid_block_allocator(allocator);
	}
}

MP_ATTR mp_bool MP_CALL mp_debug_overflow_check(const void* ptr, size_t size)
{
	MP_INVARIANT(ptr != NULL);
	return mp_check_redzone(ptr, size);
}
MP_EXTERN_C_END
#endif
#endif