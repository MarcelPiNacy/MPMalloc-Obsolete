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

#ifndef MPMM_INCLUDED
#define MPMM_INCLUDED
#include <stdint.h>
#include <stddef.h>

#if !defined(MPMM_DEBUG) && (defined(_DEBUG) || !defined(NDEBUG))
#define MPMM_DEBUG
#endif

#ifndef MPMM_CALL
#define MPMM_CALL
#endif

#ifndef MPMM_ATTR
#define MPMM_ATTR
#endif

#ifndef MPMM_PTR
#define MPMM_PTR
#endif

#ifndef MPMM_SPIN_THRESHOLD
#define MPMM_SPIN_THRESHOLD 16
#endif

#ifndef MPMM_CACHE_LINE_SIZE
#define MPMM_CACHE_LINE_SIZE 64
#endif

#ifdef MPMM_DEBUG
#define MPMM_CHECK_OVERFLOW
#endif

#if !defined(MPMM_REDZONE_SIZE) && defined(MPMM_CHECK_OVERFLOW)
#define MPMM_REDZONE_SIZE 8
#endif

#if !defined(MPMM_REDZONE_VALUE) && defined(MPMM_CHECK_OVERFLOW)
#define MPMM_REDZONE_VALUE 0xab
#endif

#ifndef MPMM_NODISCARD
#define MPMM_NODISCARD
#ifdef __cplusplus
#if __cplusplus >= 201703L
#undef MPMM_NODISCARD
#define MPMM_NODISCARD [[nodiscard]]
#endif
#endif
#endif

#ifdef __cplusplus
typedef bool mpmm_bool;
#define MPMM_EXTERN_C_BEGIN extern "C" {
#define MPMM_EXTERN_C_END }
#else
typedef _Bool mpmm_bool;
#define MPMM_EXTERN_C_BEGIN
#define MPMM_EXTERN_C_END
#endif

MPMM_EXTERN_C_BEGIN
typedef enum mpmm_malloc_flag_bits
{
	MPMM_ENABLE_FALLBACK = 1,
} mpmm_malloc_flag_bits;
typedef uint64_t mpmm_flags;

typedef enum mpmm_flush_type
{
	MPMM_FLUSH_FULL,
	MPMM_FLUSH_EXPONENTIAL,
} mpmm_flush_type;

typedef void(MPMM_PTR* mpmm_fn_init)();
typedef void(MPMM_PTR* mpmm_fn_cleanup)();
typedef void*(MPMM_PTR* mpmm_fn_malloc)(size_t size);
typedef mpmm_bool(MPMM_PTR* mpmm_fn_resize)(void* ptr, size_t old_size, size_t new_size);
typedef void*(MPMM_PTR* mpmm_fn_realloc)(void* ptr, size_t old_size, size_t new_size);
typedef void(MPMM_PTR* mpmm_fn_free)(void* ptr, size_t size);
typedef void(MPMM_PTR* mpmm_fn_purge)(void* ptr, size_t size);
typedef void(MPMM_PTR *mpmm_fn_debugger_message)(void* context, const char* message, size_t size);
typedef void(MPMM_PTR *mpmm_fn_debugger_warning)(void* context, const char* message, size_t size);
typedef void(MPMM_PTR *mpmm_fn_debugger_error)(void* context, const char* message, size_t size);

typedef struct mpmm_backend_options
{
	mpmm_fn_init init;
	mpmm_fn_cleanup cleanup;
	mpmm_fn_malloc malloc;
	mpmm_fn_resize resize;
	mpmm_fn_free free;
	mpmm_fn_purge purge;
} mpmm_backend_options;

typedef struct mpmm_init_options
{
	size_t expected_concurrency;
	const mpmm_backend_options* backend;
} mpmm_init_options;

typedef struct mpmm_mem_stats
{
	size_t allocation_count;
	size_t deallocation_count;
	size_t active_memory;
	size_t idle_memory;
	size_t record_concurrency;
} mpmm_mem_stats;

typedef struct mpmm_trim_options
{
	size_t trim_limit;
} mpmm_trim_options;

typedef struct mpmm_debugger_options
{
	void* context;
	mpmm_fn_debugger_message message;
	mpmm_fn_debugger_warning warning;
	mpmm_fn_debugger_error error;
} mpmm_debugger_options;

typedef struct mpmm_global_params
{
	size_t page_size;
	size_t chunk_size;
	size_t expected_concurrency;
} mpmm_global_params;

MPMM_ATTR void					MPMM_CALL mpmm_init_info_default(mpmm_init_options* out_options);
MPMM_ATTR void					MPMM_CALL mpmm_trim_options_default(mpmm_trim_options* out_options);
MPMM_ATTR void					MPMM_CALL mpmm_debugger_options_default(mpmm_debugger_options* out_options);

MPMM_ATTR void					MPMM_CALL mpmm_init(const mpmm_init_options* options);
MPMM_ATTR mpmm_bool				MPMM_CALL mpmm_is_initialized();
MPMM_ATTR void					MPMM_CALL mpmm_cleanup();

MPMM_ATTR void					MPMM_CALL mpmm_thread_init();
MPMM_ATTR void					MPMM_CALL mpmm_thread_cleanup();

MPMM_ATTR void					MPMM_CALL mpmm_stats(mpmm_mem_stats* out_stats);
MPMM_ATTR void					MPMM_CALL mpmm_params(mpmm_global_params* out_params);

MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_malloc(size_t size);
MPMM_ATTR mpmm_bool				MPMM_CALL mpmm_resize(void* ptr, size_t old_size, size_t new_size);
MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_realloc(void* ptr, size_t old_size, size_t new_size);
MPMM_ATTR void					MPMM_CALL mpmm_free(void* ptr, size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_round_size(size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_purge(mpmm_flags flags, void* param);
MPMM_ATTR size_t				MPMM_CALL mpmm_trim(const mpmm_trim_options* options);

MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_tcache_malloc(size_t size, mpmm_flags flags);
MPMM_ATTR void					MPMM_CALL mpmm_tcache_free(void* ptr, size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_tcache_round_size(size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_tcache_flush(mpmm_flags flags, void* param);
MPMM_ATTR size_t				MPMM_CALL mpmm_tcache_min_size();
MPMM_ATTR size_t				MPMM_CALL mpmm_tcache_max_size();

MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_lcache_malloc(size_t size, mpmm_flags flags);
MPMM_ATTR void					MPMM_CALL mpmm_lcache_free(void* ptr, size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_lcache_round_size(size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_lcache_flush(mpmm_flags flags, void* param);
MPMM_ATTR size_t				MPMM_CALL mpmm_lcache_min_size();
MPMM_ATTR size_t				MPMM_CALL mpmm_lcache_max_size();

MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_persistent_malloc(size_t size);
MPMM_ATTR void					MPMM_CALL mpmm_persistent_cleanup();

MPMM_ATTR size_t				MPMM_CALL mpmm_backend_required_alignment();
MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_backend_malloc(size_t size);
MPMM_ATTR mpmm_bool				MPMM_CALL mpmm_backend_resize(void* ptr, size_t old_size, size_t new_size);
MPMM_ATTR void					MPMM_CALL mpmm_backend_free(void* ptr, size_t size);
MPMM_ATTR void					MPMM_CALL mpmm_backend_purge(void* ptr, size_t size);

MPMM_ATTR void					MPMM_CALL mpmm_debugger_init(const mpmm_debugger_options* options);
MPMM_ATTR mpmm_bool				MPMM_CALL mpmm_debugger_enabled();
MPMM_ATTR void					MPMM_CALL mpmm_debugger_message(const char* message, size_t size);
MPMM_ATTR void					MPMM_CALL mpmm_debugger_warning(const char* message, size_t size);
MPMM_ATTR void					MPMM_CALL mpmm_debugger_error(const char* message, size_t size);
MPMM_EXTERN_C_END

#if defined(__cplusplus) && defined(MPMM_CXX_API)
namespace mpmm
{
	struct init_options : mpmm_init_options
	{
		inline MPMM_ATTR MPMM_CALL init_options() noexcept { mpmm_init_info_default((mpmm_init_options*)this); }
		~init_options() = default;
	};

	using memory_stats = mpmm_mem_stats;

	struct trim_options : mpmm_trim_options
	{
		inline MPMM_ATTR MPMM_CALL trim_options() noexcept { mpmm_trim_options_default((mpmm_trim_options*)this); }
		~trim_options() = default;
	};

	struct debugger_options : mpmm_debugger_options
	{
		inline MPMM_ATTR MPMM_CALL debugger_options() noexcept { mpmm_debugger_options_default((mpmm_debugger_options*)this); }
		~debugger_options() = default;
	};

	MPMM_ATTR void			MPMM_CALL init(const mpmm_init_options* options) noexcept { return mpmm_init(options); }
	MPMM_ATTR void			MPMM_CALL cleanup() noexcept { mpmm_cleanup(); }
	MPMM_ATTR memory_stats	MPMM_CALL stats() noexcept { mpmm_mem_stats r; mpmm_stats(&r); return r; }
	MPMM_ATTR void*			MPMM_CALL malloc(size_t size) noexcept { return mpmm_malloc(size); }
	MPMM_ATTR bool			MPMM_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept { return mpmm_resize(ptr, old_size, new_size); }
	MPMM_ATTR void*			MPMM_CALL realloc(void* ptr, size_t old_size, size_t new_size) noexcept { return mpmm_realloc(ptr, old_size, new_size); }
	MPMM_ATTR void			MPMM_CALL free(void* ptr, size_t size) noexcept { mpmm_free(ptr, size); }
	MPMM_ATTR size_t		MPMM_CALL round_size(size_t size) noexcept { return mpmm_round_size(size); }
	MPMM_ATTR size_t		MPMM_CALL purge(mpmm_flags flags, void* param) noexcept { return mpmm_purge(flags, param); }
	MPMM_ATTR size_t		MPMM_CALL trim(const trim_options* options) noexcept { return mpmm_trim((const mpmm_trim_options*)options); }

	namespace thread_cache
	{
		MPMM_ATTR void*		MPMM_CALL malloc(size_t size, mpmm_flags flags) noexcept { return mpmm_tcache_malloc(size, flags); }
		MPMM_ATTR void		MPMM_CALL free(void* ptr, size_t size) noexcept { mpmm_tcache_free(ptr, size); }
		MPMM_ATTR size_t	MPMM_CALL round_size(size_t size) noexcept { return mpmm_tcache_round_size(size); }
		MPMM_ATTR size_t	MPMM_CALL flush(mpmm_flags flags, void* param) noexcept { return mpmm_tcache_flush(flags, param); }
		MPMM_ATTR size_t	MPMM_CALL min_size() noexcept { return mpmm_tcache_min_size(); }
		MPMM_ATTR size_t	MPMM_CALL max_size() noexcept { return mpmm_tcache_max_size(); }
	}

	namespace large_cache
	{
		MPMM_ATTR void*		MPMM_CALL malloc(size_t size, mpmm_flags flags) noexcept { return mpmm_lcache_malloc(size, flags); }
		MPMM_ATTR void		MPMM_CALL free(void* ptr, size_t size) noexcept { mpmm_lcache_free(ptr, size); }
		MPMM_ATTR size_t	MPMM_CALL round_size(size_t size) noexcept { return mpmm_lcache_round_size(size); }
		MPMM_ATTR size_t	MPMM_CALL flush(mpmm_flags flags, void* param) noexcept { return mpmm_lcache_flush(flags, param); }
		MPMM_ATTR size_t	MPMM_CALL min_size() noexcept { return mpmm_lcache_min_size(); }
		MPMM_ATTR size_t	MPMM_CALL max_size() noexcept { return mpmm_lcache_max_size(); }
	}

	namespace persistent
	{
		MPMM_ATTR void*		MPMM_CALL malloc(size_t size) noexcept { return mpmm_persistent_malloc(size); }
		MPMM_ATTR void		MPMM_CALL cleanup() noexcept { mpmm_persistent_cleanup(); }
	}

	namespace backend
	{
		MPMM_ATTR size_t	MPMM_CALL required_alignment() noexcept { return mpmm_backend_required_alignment(); }
		MPMM_ATTR void*		MPMM_CALL malloc(size_t size) noexcept { return mpmm_backend_malloc(size); }
		MPMM_ATTR bool		MPMM_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept { return mpmm_backend_resize(ptr, old_size, new_size); }
		MPMM_ATTR void		MPMM_CALL free(void* ptr, size_t size) noexcept { return mpmm_backend_free(ptr, size); }
		MPMM_ATTR void		MPMM_CALL purge(void* ptr, size_t size) noexcept { return mpmm_backend_free(ptr, size); }
	}

	namespace debugger
	{
		MPMM_ATTR void		MPMM_CALL init(const debugger_options* options) noexcept { return mpmm_debugger_init((const mpmm_debugger_options*)options); }
		MPMM_ATTR bool		MPMM_CALL enabled() noexcept { return mpmm_debugger_enabled(); }
		MPMM_ATTR void		MPMM_CALL message(const char* message, size_t size) noexcept { return mpmm_debugger_message(message, size); }
		MPMM_ATTR void		MPMM_CALL warning(const char* message, size_t size) noexcept { return mpmm_debugger_warning(message, size); }
		MPMM_ATTR void		MPMM_CALL error(const char* message, size_t size) noexcept { return mpmm_debugger_error(message, size); }
	}
}
#endif



#ifdef MPMM_IMPLEMENTATION

#include <stdbool.h>

#if UINT32_MAX == UINTPTR_MAX
#define MPMM_32BIT
#else
#define MPMM_64BIT
#endif

#ifndef MPMM_JUNK_VALUE
#define MPMM_JUNK_VALUE 0xcd
#endif

#ifdef MPMM_CHECK_OVERFLOW
#define MPMM_UPDATE_SIZE(K) ((K) + MPMM_REDZONE_SIZE)
#else
#define MPMM_UPDATE_SIZE(K) (K)
#endif

#ifdef __cplusplus
#define MPMM_TLS thread_local
#else
#define MPMM_TLS _Thread_local
#endif

#ifdef MPMM_DEBUG
#define MPMM_DEBUG_JUNK_FILL(P, K) MPMM_UNLIKELY_IF((P) != NULL) (void)memset((P), MPMM_JUNK_VALUE, (K))
#else
#define MPMM_DEBUG_JUNK_FILL(P, K)
#endif

#define MPMM_ALIGN_FLOOR(VALUE, ALIGNMENT) ((VALUE) & ~((ALIGNMENT) - 1))
#define MPMM_ALIGN_ROUND(VALUE, ALIGNMENT) ((VALUE + ((ALIGNMENT) - 1)) & ~((ALIGNMENT) - 1))
#define MPMM_ALIGN_FLOOR_LOG2(VALUE, ALIGNMENT_LOG2) MPMM_ALIGN_FLOOR(VALUE, ((size_t)1 << (size_t)ALIGNMENT_LOG2))
#define MPMM_ALIGN_ROUND_LOG2(VALUE, ALIGNMENT_LOG2) MPMM_ALIGN_ROUND(VALUE, ((size_t)1 << (size_t)ALIGNMENT_LOG2))

#ifdef _WIN32
#define MPMM_WINDOWS
#include <Windows.h>
#elif defined(__linux__) || defined(__LINUX__)
#define MPMM_LINUX
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#else
#error "MPMALLOC: UNSUPPORTED OS"
#endif

#ifdef __cplusplus
#define MPMM_ALIGNAS(SIZE) alignas((SIZE))
#endif

#if defined(__clang__) || defined(__GNUC__)
#define MPMM_CLANG_OR_GCC
#if defined(__x86_64__) || defined(__i386__)
#define MPMM_SPIN_WAIT __builtin_ia32_pause()
#elif defined(__arm__)
#define MPMM_SPIN_WAIT __yield()
#endif
#ifndef __cplusplus
#define MPMM_ALIGNAS(SIZE) __attribute__((aligned((SIZE))))
#endif
#define MPMM_PURE __attribute__((pure))
#define MPMM_ULTRAPURE __attribute__((pure))
#define MPMM_PREFETCH(PTR) __builtin_prefetch((PTR), 1, 3)
#define MPMM_EXPECT(CONDITION, VALUE) __builtin_expect((long)(CONDITION), (VALUE))
#define MPMM_LIKELY_IF(CONDITION) if (MPMM_EXPECT(CONDITION, 1))
#define MPMM_UNLIKELY_IF(CONDITION) if (MPMM_EXPECT(CONDITION, 0))
#define MPMM_POPCNT32(MASK) __builtin_popcount((MASK))
#define MPMM_POPCNT64(MASK) __builtin_popcountll((MASK))
#define MPMM_CTZ32(MASK) __builtin_ctz((MASK))
#define MPMM_CTZ64(MASK) __builtin_ctzll((MASK))
#define MPMM_CLZ32(MASK) __builtin_clz((MASK))
#define MPMM_CLZ64(MASK) __builtin_clzll((MASK))
#ifdef MPMM_DEBUG
#define MPMM_INLINE_ALWAYS
#define MPMM_INLINE_NEVER
#else
#define MPMM_INLINE_ALWAYS __attribute__((always_inline))
#define MPMM_INLINE_NEVER __attribute__((noinline))
#endif
#define MPMM_ASSUME(EXPRESSION) __builtin_assume((EXPRESSION))
#elif defined(_MSVC_LANG)
#define MPMM_MSVC
#include <intrin.h>
#if defined(_M_X64) || defined(_M_IX86)
#define MPMM_SPIN_WAIT _mm_pause()
#define MPMM_PREFETCH(PTR) _mm_prefetch((const CHAR*)(PTR), _MM_HINT_T0)
#elif defined(_M_ARM)
#define MPMM_SPIN_WAIT __yield()
#define MPMM_PREFETCH(PTR) __prefetch((const CHAR*)(PTR))
#endif
#ifndef __cplusplus
#define MPMM_ALIGNAS(SIZE) __declspec(align(SIZE))
#endif
#define MPMM_PURE
#define MPMM_ULTRAPURE __declspec(noalias)
#define MPMM_EXPECT(CONDITION, VALUE) (CONDITION)
#define MPMM_LIKELY_IF(CONDITION) if ((CONDITION))
#define MPMM_UNLIKELY_IF(CONDITION) if ((CONDITION))
#ifdef _M_ARM
#define MPMM_POPCNT32(MASK) (uint_fast8_t)_CountOneBits((MASK))
#define MPMM_POPCNT64(MASK) (uint_fast8_t)_CountOneBits64((MASK))
#define MPMM_CTZ32(MASK) (uint_fast8_t)_CountLeadingZeros(_arm_rbit((MASK)))
#define MPMM_CTZ64(MASK) (uint_fast8_t)_CountLeadingZeros64((((uint64_t)_arm_rbit((uint32_t)(MASK))) << 32) | (uint64_t)_arm_rbit(((uint32_t)(MASK)) >> 32))
#define MPMM_CLZ32(MASK) (uint_fast8_t)_CountLeadingZeros((MASK))
#define MPMM_CLZ64(MASK) (uint_fast8_t)_CountLeadingZeros64((MASK))
#else
#define MPMM_POPCNT32(MASK) (uint_fast8_t)__popcnt((MASK))
#define MPMM_POPCNT64(MASK) (uint_fast8_t)__popcnt64((MASK))
#define MPMM_CTZ32(MASK) (uint_fast8_t)_tzcnt_u32((MASK))
#define MPMM_CTZ64(MASK) (uint_fast8_t)_tzcnt_u64((MASK))
#define MPMM_CLZ32(MASK) (uint_fast8_t)_lzcnt_u32((MASK))
#define MPMM_CLZ64(MASK) (uint_fast8_t)_lzcnt_u64((MASK))
#endif
#ifdef MPMM_DEBUG
#define MPMM_INLINE_ALWAYS
#define MPMM_INLINE_NEVER
#else
#define MPMM_INLINE_ALWAYS __forceinline
#define MPMM_INLINE_NEVER __declspec(noinline)
#endif
#define MPMM_ASSUME(EXPRESSION) __assume((EXPRESSION))
#else
#error "MPMALLOC: UNSUPPORTED COMPILER"
#endif

#ifdef MPMM_DEBUG
#include <assert.h>
#include <stdlib.h>
#define MPMM_INVARIANT(EXPRESSION) assert(EXPRESSION)
#define MPMM_UNREACHABLE abort()
#else
#define MPMM_INVARIANT(EXPRESSION) MPMM_ASSUME(EXPRESSION)
#define MPMM_UNREACHABLE MPMM_ASSUME(0)
#endif

#define MPMM_BT32(MASK, INDEX) ((MASK) & (1U << (INDEX)))
#define MPMM_BT64(MASK, INDEX) ((MASK) & (1ULL << (INDEX)))
#define MPMM_BS32(MASK, INDEX) (MASK) |= (1U << (INDEX))
#define MPMM_BS64(MASK, INDEX) (MASK) |= (1ULL << (INDEX))
#define MPMM_BR32(MASK, INDEX) (MASK) &= ~(1U << (INDEX))
#define MPMM_BR64(MASK, INDEX) (MASK) &= ~(1ULL << (INDEX))
#define MPMM_LOG2_32(VALUE) (uint8_t)(31 - MPMM_CLZ32(VALUE))
#define MPMM_LOG2_64(VALUE) (uint8_t)(63 - MPMM_CLZ64(VALUE))
#define MPMM_POW2_ROUND32(VALUE) (1U << (32 - MPMM_CLZ32((VALUE) - 1U)))
#define MPMM_POW2_ROUND64(VALUE) (1ULL << (64 - MPMM_CLZ64((VALUE) - 1ULL)))

#ifdef MPMM_32BIT
#define MPMM_POINTER_SIZE_LOG2 2
#define MPMM_POPCNT(MASK) MPMM_POPCNT32((MASK))
#define MPMM_CTZ(MASK) MPMM_CTZ32((MASK))
#define MPMM_CLZ(MASK) MPMM_CLZ32((MASK))
#define MPMM_LOG2(VALUE) MPMM_LOG2_32(VALUE)
#define MPMM_POW2_ROUND(VALUE) MPMM_POW2_ROUND32(VALUE)
#define MPMM_BT(MASK, INDEX) MPMM_BT32(MASK, INDEX)
#define MPMM_BS(MASK, INDEX) MPMM_BS32(MASK, INDEX)
#define MPMM_BR(MASK, INDEX) MPMM_BR32(MASK, INDEX)
#else
#define MPMM_POINTER_SIZE_LOG2 3
#define MPMM_POPCNT(MASK) MPMM_POPCNT64((MASK))
#define MPMM_CTZ(MASK) MPMM_CTZ64((MASK))
#define MPMM_CLZ(MASK) MPMM_CLZ64((MASK))
#define MPMM_LOG2(VALUE) MPMM_LOG2_64(VALUE)
#define MPMM_POW2_ROUND(VALUE) MPMM_POW2_ROUND64(VALUE)
#define MPMM_BT(MASK, INDEX) MPMM_BT64(MASK, INDEX)
#define MPMM_BS(MASK, INDEX) MPMM_BS64(MASK, INDEX)
#define MPMM_BR(MASK, INDEX) MPMM_BR64(MASK, INDEX)
#endif

#define MPMM_ARRAY_SIZE(ARRAY) (sizeof(ARRAY) / sizeof(ARRAY[0]))
#define MPMM_BLOCK_MASK_BIT_SIZE_LOG2 (sizeof(size_t) == 4 ? 5 : 6)
#define MPMM_BLOCK_MASK_MOD_MASK ((1UI8 << MPMM_BLOCK_MASK_BIT_SIZE_LOG2) - 1UI8)
#define MPMM_BLOCK_ALLOCATOR_MAX_CAPACITY (MPMM_CACHE_LINE_SIZE * 8)
#define MPMM_BLOCK_ALLOCATOR_MASK_COUNT (MPMM_BLOCK_ALLOCATOR_MAX_CAPACITY / (8 * sizeof(size_t)))
#define MPMM_SHARED_ATTR alignas(MPMM_CACHE_LINE_SIZE)

#ifdef MPMM_DEBUG
#define MPMM_EMMIT_MESSAGE(MESSAGE) mpmm_debugger_message((MESSAGE), (sizeof((MESSAGE)) / sizeof((MESSAGE)[0])) - 1)
#define MPMM_EMMIT_WARNING(MESSAGE) mpmm_debugger_warning((MESSAGE), (sizeof((MESSAGE)) / sizeof((MESSAGE)[0])) - 1)
#define MPMM_EMMIT_ERROR(MESSAGE) mpmm_debugger_error((MESSAGE), (sizeof((MESSAGE)) / sizeof((MESSAGE)[0])) - 1)
#else
#define MPMM_EMMIT_MESSAGE(MESSAGE)
#define MPMM_EMMIT_WARNING(MESSAGE)
#define MPMM_EMMIT_ERROR(MESSAGE)
#endif

#ifdef MPMM_DEBUG
static_assert((MPMM_REDZONE_SIZE & ((UINTMAX_C(1) << MPMM_POINTER_SIZE_LOG2) - UINTMAX_C(1))) == 0, "Error, MPMM_REDZONE_SIZE must be a multiple of sizeof(size_t).");
#endif

// ================================================================
//	ATOMIC INTRINSICS
// ================================================================

#ifdef MPMM_CLANG_OR_GCC
#define MPMM_ATOMIC(TYPE) TYPE volatile
#define MPMM_ATOMIC_TEST_ACQ(WHERE)								__atomic_load_n((mpmm_atomic_bool*)(WHERE), __ATOMIC_ACQUIRE)
#define MPMM_ATOMIC_TAS_ACQ(WHERE)								__atomic_test_and_set((mpmm_atomic_bool*)(WHERE), __ATOMIC_ACQUIRE)
#define MPMM_ATOMIC_CLEAR_REL(WHERE)							__atomic_clear((mpmm_atomic_bool*)(WHERE), __ATOMIC_RELEASE)
#define MPMM_ATOMIC_LOAD_ACQ_UPTR(WHERE)						__atomic_load_n((mpmm_atomic_size_t*)(WHERE), __ATOMIC_ACQUIRE)
#define MPMM_ATOMIC_STORE_REL_UPTR(WHERE, VALUE)				__atomic_store_n((mpmm_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_RELEASE)
#define MPMM_ATOMIC_SWAP_ACQ_UPTR(WHERE, VALUE)					__atomic_exchange_n((mpmm_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_ACQUIRE)
#define MPMM_ATOMIC_CAS_ACQ_UPTR(WHERE, EXPECTED, VALUE)		__atomic_compare_exchange_n((mpmm_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MPMM_ATOMIC_CAS_REL_UPTR(WHERE, EXPECTED, VALUE)		__atomic_compare_exchange_n((mpmm_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED)
#define MPMM_ATOMIC_CAS_WEAK_ACQ_UPTR(WHERE, EXPECTED, VALUE)	__atomic_compare_exchange_n((mpmm_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), 1, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)
#define MPMM_ATOMIC_CAS_WEAK_REL_UPTR(WHERE, EXPECTED, VALUE)	__atomic_compare_exchange_n((mpmm_atomic_size_t*)(WHERE), (size_t*)(EXPECTED), (size_t)(VALUE), 1, __ATOMIC_RELEASE, __ATOMIC_RELAXED)
#define MPMM_ATOMIC_FAA_ACQ(WHERE, VALUE)						__atomic_fetch_add((mpmm_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_ACQUIRE)
#define MPMM_ATOMIC_FAS_REL(WHERE, VALUE)						__atomic_fetch_sub((mpmm_atomic_size_t*)(WHERE), (size_t)(VALUE), __ATOMIC_RELEASE)
#define MPMM_ATOMIC_BIT_SET_REL(WHERE, VALUE)					(void)__atomic_fetch_or((mpmm_atomic_size_t*)(WHERE), (size_t)1 << (uint_fast8_t)(VALUE), __ATOMIC_RELEASE)
#elif defined(MPMM_MSVC)
// I'd like to give special thanks to the visual studio devteam for being more than 10 years ahead of the competition in not adding support to the C11 standard to their compiler.
#define MPMM_ATOMIC(TYPE) TYPE volatile
#ifdef _M_ARM
#define MPMM_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(NAME) NAME##_acq
#define MPMM_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(NAME) NAME##_rel
#else
#define MPMM_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(NAME) NAME
#define MPMM_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(NAME) NAME
#endif
#ifdef MPMM_32BIT
typedef LONG mpmm_msvc_size_t;
#define MPMM_MSVC_ATOMIC_ACQ(NAME) MPMM_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(NAME)
#define MPMM_MSVC_ATOMIC_REL(NAME) MPMM_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(NAME)
#else
typedef LONG64 mpmm_msvc_size_t;
#define MPMM_MSVC_ATOMIC_ACQ(NAME) MPMM_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(NAME##64)
#define MPMM_MSVC_ATOMIC_REL(NAME) MPMM_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(NAME##64)
#endif
typedef CHAR mpmm_msvc_bool;
typedef volatile CHAR mpmm_msvc_atomic_bool;
typedef volatile mpmm_msvc_size_t mpmm_msvc_atomic_size_t;
#define MPMM_ATOMIC_TEST_ACQ(WHERE)								(mpmm_bool)MPMM_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(_InterlockedOr8)((mpmm_msvc_atomic_bool*)(WHERE), (mpmm_msvc_bool)0)
#define MPMM_ATOMIC_TAS_ACQ(WHERE)								(mpmm_bool)MPMM_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(_InterlockedExchange8)((mpmm_msvc_atomic_bool*)(WHERE), (mpmm_msvc_bool)1)
#define MPMM_ATOMIC_CLEAR_REL(WHERE)							(void)MPMM_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(_InterlockedExchange8)((mpmm_msvc_atomic_bool*)(WHERE), (mpmm_msvc_bool)0)
#define MPMM_ATOMIC_LOAD_ACQ_UPTR(WHERE)						MPMM_MSVC_ATOMIC_ACQ(_InterlockedOr)((mpmm_msvc_atomic_size_t*)(WHERE), 0)
#define MPMM_ATOMIC_STORE_REL_UPTR(WHERE, VALUE)				(void)MPMM_MSVC_ATOMIC_REL(_InterlockedExchange)((mpmm_msvc_atomic_size_t*)(WHERE), (mpmm_msvc_size_t)(VALUE))
#define MPMM_ATOMIC_SWAP_ACQ_UPTR(WHERE, VALUE)					MPMM_MSVC_ATOMIC_ACQ(_InterlockedExchange)((mpmm_msvc_atomic_size_t*)(WHERE), (mpmm_msvc_size_t)(VALUE))
#define MPMM_ATOMIC_CAS_ACQ_UPTR(WHERE, EXPECTED, VALUE)		(MPMM_MSVC_ATOMIC_ACQ(_InterlockedCompareExchange)((mpmm_msvc_atomic_size_t*)(WHERE), *(const mpmm_msvc_size_t*)(EXPECTED), (mpmm_msvc_size_t)(VALUE)) == *(const mpmm_msvc_size_t*)EXPECTED)
#define MPMM_ATOMIC_CAS_REL_UPTR(WHERE, EXPECTED, VALUE)		(MPMM_MSVC_ATOMIC_REL(_InterlockedCompareExchange)((mpmm_msvc_atomic_size_t*)(WHERE), *(const mpmm_msvc_size_t*)(EXPECTED), (mpmm_msvc_size_t)(VALUE)) == *(const mpmm_msvc_size_t*)EXPECTED)
#define MPMM_ATOMIC_CAS_WEAK_ACQ_UPTR(WHERE, EXPECTED, VALUE)	(MPMM_MSVC_ATOMIC_ACQ(_InterlockedCompareExchange)((mpmm_msvc_atomic_size_t*)(WHERE), *(const mpmm_msvc_size_t*)(EXPECTED), (mpmm_msvc_size_t)(VALUE)) == *(const mpmm_msvc_size_t*)EXPECTED)
#define MPMM_ATOMIC_CAS_WEAK_REL_UPTR(WHERE, EXPECTED, VALUE)	(MPMM_MSVC_ATOMIC_REL(_InterlockedCompareExchange)((mpmm_msvc_atomic_size_t*)(WHERE), *(const mpmm_msvc_size_t*)(EXPECTED), (mpmm_msvc_size_t)(VALUE)) == *(const mpmm_msvc_size_t*)EXPECTED)
#define MPMM_ATOMIC_FAA_ACQ(WHERE, VALUE)						(size_t)MPMM_MSVC_ATOMIC_ACQ(_InterlockedExchangeAdd)((mpmm_msvc_atomic_size_t*)(WHERE), (mpmm_msvc_size_t)(VALUE))
#define MPMM_ATOMIC_FAS_REL(WHERE, VALUE)						(size_t)MPMM_MSVC_ATOMIC_REL(_InterlockedExchangeAdd)((mpmm_msvc_atomic_size_t*)(WHERE), -(mpmm_msvc_size_t)(VALUE))
#define MPMM_ATOMIC_BIT_SET_REL(WHERE, VALUE)					(void)MPMM_MSVC_ATOMIC_REL(_interlockedbittestandset)((mpmm_msvc_atomic_size_t*)(WHERE), (uint_fast8_t)(VALUE))
#define MPMM_ATOMIC_WIDE_CAS_WEAK_ACQ(WHERE, EXPECTED, VALUE)	MPMM_MSVC_ATOMIC_ACQUIRE_FENCE_SUFFIX(_InterlockedCompareExchange128)((WHERE), ((const mpmm_msvc_size_t*)(EXPECTED))[1], ((const mpmm_msvc_size_t*)(EXPECTED))[0], &(DESIRED))
#define MPMM_ATOMIC_WIDE_CAS_WEAK_REL(WHERE, EXPECTED, VALUE)	MPMM_MSVC_ATOMIC_RELEASE_FENCE_SUFFIX(_InterlockedCompareExchange128)((WHERE), ((const mpmm_msvc_size_t*)(EXPECTED))[1], ((const mpmm_msvc_size_t*)(EXPECTED))[0], &(DESIRED))
#endif

#define MPMM_ATOMIC_LOAD_ACQ_PTR(WHERE)							(void*)MPMM_ATOMIC_LOAD_ACQ_UPTR((mpmm_atomic_size_t*)WHERE)
#define MPMM_ATOMIC_STORE_REL_PTR(WHERE, VALUE)					MPMM_ATOMIC_STORE_REL_UPTR((mpmm_atomic_size_t*)WHERE, (size_t)VALUE)
#define MPMM_ATOMIC_SWAP_ACQ_PTR(WHERE, VALUE)					(void*)MPMM_ATOMIC_SWAP_ACQ_UPTR((mpmm_atomic_size_t*)WHERE, (size_t)VALUE)
#define MPMM_ATOMIC_CAS_ACQ_PTR(WHERE, EXPECTED, VALUE)			MPMM_ATOMIC_CAS_ACQ_UPTR((mpmm_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)
#define MPMM_ATOMIC_CAS_REL_PTR(WHERE, EXPECTED, VALUE)			MPMM_ATOMIC_CAS_REL_UPTR((mpmm_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)
#define MPMM_ATOMIC_WCAS_ACQ_PTR(WHERE, EXPECTED, VALUE)		MPMM_ATOMIC_CAS_WEAK_ACQ_UPTR((mpmm_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)
#define MPMM_ATOMIC_WCAS_REL_PTR(WHERE, EXPECTED, VALUE)		MPMM_ATOMIC_CAS_WEAK_REL_UPTR((mpmm_atomic_size_t*)WHERE, (size_t*)EXPECTED, (size_t)VALUE)

// ================================================================
//	SIZE CLASS MAPPING FUNCTIONS
// ================================================================

static const uint_fast16_t MPMM_SIZE_MAP_0[] = { 1 };
static const uint_fast16_t MPMM_SIZE_MAP_1[] = { 2 };
static const uint_fast16_t MPMM_SIZE_MAP_2[] = { 4 };
static const uint_fast16_t MPMM_SIZE_MAP_3[] = { 8 };
static const uint_fast16_t MPMM_SIZE_MAP_4[] = { 16 };
static const uint_fast16_t MPMM_SIZE_MAP_5[] = { 32 };
static const uint_fast16_t MPMM_SIZE_MAP_6[] = { 64 };
static const uint_fast16_t MPMM_SIZE_MAP_7[] = { 128, 144, 160, 176, 192, 208, 224, 240 };
static const uint_fast16_t MPMM_SIZE_MAP_8[] = { 256, 272, 288, 304, 320, 352, 384, 416, 448, 480 };
static const uint_fast16_t MPMM_SIZE_MAP_9[] = { 512, 544, 576, 640, 704, 768, 832, 896, 960 };
static const uint_fast16_t MPMM_SIZE_MAP_10[] = { 1024, 1088, 1152, 1280, 1408, 1536, 1664, 1792, 1920 };
static const uint_fast16_t MPMM_SIZE_MAP_11[] = { 2048, 2176, 2304, 2560, 2816, 3072, 3328, 3584, 3840 };

static const uint_fast16_t* const MPMM_SIZE_CLASS_LOOKUP[] =
{
	MPMM_SIZE_MAP_0, MPMM_SIZE_MAP_1, MPMM_SIZE_MAP_2, MPMM_SIZE_MAP_3,
	MPMM_SIZE_MAP_4, MPMM_SIZE_MAP_5, MPMM_SIZE_MAP_6, MPMM_SIZE_MAP_7,
	MPMM_SIZE_MAP_8, MPMM_SIZE_MAP_9, MPMM_SIZE_MAP_10, MPMM_SIZE_MAP_11
};

static const uint8_t MPMM_SIZE_MAP_SIZES[] =
{
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0), MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1), MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2), MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4), MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5), MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6), MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_7),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_8), MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_9), MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_10), MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_11)
};

static const uint8_t MPMM_SIZE_CLASS_COUNT =
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_7) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_8) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_9) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_10) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_11);

static const uint8_t MPMM_SIZE_MAP_OFFSETS[] =
{
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_7) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_8) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_7) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_9) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_8) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_7) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_10) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_9) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_8) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_7) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)),
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_11) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_10) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_9) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_8) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_7) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0)) // AAAAAAAGH!!!
};

#define MPMM_SIZE_MAP_SIZE MPMM_ARRAY_SIZE(MPMM_SIZE_CLASS_LOOKUP)
#define MPMM_SMALL_SIZE_CLASS_COUNT MPMM_ARRAY_SIZE(MPMM_SMALL_SIZE_CLASSES)

typedef MPMM_ATOMIC(mpmm_bool) mpmm_atomic_bool;
typedef MPMM_ATOMIC(size_t) mpmm_atomic_size_t;
typedef MPMM_ATOMIC(void*) mpmm_atomic_address;

static const size_t tcache_small_bin_buffer_size = sizeof(void*) * MPMM_SIZE_CLASS_COUNT;

#ifdef MPMM_WINDOWS
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
#ifdef MPMM_DEBUG
static mpmm_debugger_options debugger;
#endif

#ifdef MPMM_64BIT
static bool mpmm_init_flag;
#endif

MPMM_INLINE_ALWAYS static void mpmm_sys_init()
{
#ifdef MPMM_WINDOWS
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	page_size = info.dwPageSize;
	chunk_size = page_size * MPMM_CACHE_LINE_SIZE * 8;
	max_address = info.lpMaximumApplicationAddress;
	min_chunk = (void*)MPMM_ALIGN_ROUND((size_t)info.lpMinimumApplicationAddress, chunk_size);
	expected_concurrency = info.dwNumberOfProcessors;
#else
	page_size = (size_t)getpagesize();
	chunk_size = page_size * MPMM_CACHE_LINE_SIZE * 8;
#endif
	chunk_size_mask = chunk_size - 1;
	page_size_log2 = MPMM_LOG2(page_size);
	chunk_size_log2 = MPMM_LOG2(chunk_size);
	MPMM_INVARIANT(page_size >= 4096);
	MPMM_INVARIANT(chunk_size >= (32 * 4096));
	tcache_large_bin_buffer_size = sizeof(void*) * ((size_t)chunk_size_log2 - 12);
	tcache_buffer_size = tcache_small_bin_buffer_size * 2 + tcache_large_bin_buffer_size * 2;
}

// ================================================================
//	OS / BACKEND FUNCTIONS
// ================================================================

#ifdef MPMM_WINDOWS
typedef DWORD mpmm_thread_id;
typedef PVOID(WINAPI* VirtualAlloc2_t)(HANDLE Process, PVOID BaseAddress, SIZE_T Size, ULONG AllocationType, ULONG PageProtection, MEM_EXTENDED_PARAMETER* ExtendedParameters, ULONG ParameterCount);

static HANDLE process_handle;
static VirtualAlloc2_t virtualalloc2;
static MEM_ADDRESS_REQUIREMENTS va2_addr_req;
static MEM_EXTENDED_PARAMETER va2_ext_param;

MPMM_INLINE_ALWAYS static void mpmm_os_init()
{
	process_handle = GetCurrentProcess();
	HMODULE m = GetModuleHandle(TEXT("KernelBase.DLL"));
	MPMM_INVARIANT(m != NULL);
	virtualalloc2 = (VirtualAlloc2_t)GetProcAddress(m, "VirtualAlloc2");
	va2_addr_req.Alignment = chunk_size;
	va2_addr_req.HighestEndingAddress = max_address;
	va2_addr_req.LowestStartingAddress = min_chunk;
	va2_ext_param.Type = MemExtendedParameterAddressRequirements;
	va2_ext_param.Pointer = &va2_addr_req;
}

MPMM_INLINE_ALWAYS static void* mpmm_os_malloc(size_t size)
{
	return virtualalloc2(process_handle, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &va2_ext_param, 1);
}

// VirtualAlloc lacks resizing functionality.
MPMM_INLINE_ALWAYS static mpmm_bool mpmm_os_resize(void* ptr, size_t old_size, size_t new_size) { return 0; }

MPMM_INLINE_ALWAYS static void mpmm_os_free(void* ptr, size_t size)
{
	mpmm_bool result;
	MPMM_INVARIANT(ptr != NULL);
	result = VirtualFree(ptr, 0, MEM_RELEASE);
	MPMM_INVARIANT(result);
}

MPMM_INLINE_ALWAYS static void mpmm_os_purge(void* ptr, size_t size)
{
	MPMM_INVARIANT(ptr != NULL);
	(void)DiscardVirtualMemory(ptr, size);
}
#elif defined(MPMM_LINUX)

typedef pthread_t mpmm_thread_id;

MPMM_INLINE_ALWAYS static void mpmm_os_init()
{
}

MPMM_INLINE_ALWAYS static void* mpmm_os_malloc(size_t size)
{
	uint8_t* tmp = mmap(NULL, size * 2, PROT_READ | PROT_WRITE, MAP_ANON | MAP_UNINITIALIZED, -1, 0);
	uint8_t* tmpmm_limit = base + chunk_size * 2;
	uint8_t* r = (uint8_t*)MPMM_ALIGN_FLOOR((size_t)tmp, chunk_size);
	uint8_t* r_limit = base + chunk_size;
	MPMM_LIKELY_IF(tmp != r)
		munmap(tmp, r - tmp);
	MPMM_LIKELY_IF(tmpmm_limit != r_limit)
		munmap(base_limit, tmpmm_limit - r_limit);
	return base;
}

MPMM_INLINE_ALWAYS static void mpmm_os_free(void* ptr, size_t size)
{
	MPMM_INVARIANT(ptr != NULL);
	munmap(ptr, size);
}

MPMM_INLINE_ALWAYS static void mpmm_os_purge(void* ptr, size_t size)
{
	MPMM_INVARIANT(ptr != NULL);
	madvise(ptr, size, MADV_DONTNEED);
}
#endif

typedef MPMM_ATOMIC(mpmm_thread_id) mpmm_atomic_thread_id;

static void mpmm_empty_function() { }

static mpmm_fn_init		backend_init	= mpmm_os_init;
static mpmm_fn_cleanup	backend_cleanup	= mpmm_empty_function;
static mpmm_fn_malloc	backend_malloc	= mpmm_os_malloc;
static mpmm_fn_resize	backend_resize	= mpmm_os_resize;
static mpmm_fn_free		backend_free	= mpmm_os_free;
static mpmm_fn_purge	backend_purge	= mpmm_os_purge;

// ================================================================
//	COMMON
// ================================================================

typedef struct mpmm_flist_node { struct mpmm_flist_node* next; } mpmm_flist_node;
typedef MPMM_ATOMIC(mpmm_flist_node*) mpmm_rlist;
typedef MPMM_ATOMIC(size_t) mpmm_chunk_list;

MPMM_INLINE_ALWAYS static void mpmm_chunk_list_push(mpmm_chunk_list*head, void* ptr)
{
	mpmm_flist_node* new_head = (mpmm_flist_node*)ptr;
	size_t prior, desired;
	for (;; MPMM_SPIN_WAIT)
	{
		prior = MPMM_ATOMIC_LOAD_ACQ_UPTR(head);
		new_head->next = (mpmm_flist_node*)(prior & ~chunk_size_mask);
		desired = (size_t)new_head | (((prior & chunk_size_mask) + 1) & chunk_size_mask);
		MPMM_LIKELY_IF(MPMM_ATOMIC_CAS_WEAK_REL_UPTR(head, &prior, desired))
			break;
	}
}

MPMM_INLINE_ALWAYS static void* mpmm_chunk_list_pop(mpmm_chunk_list* head)
{
	size_t prior, desired;
	for (;; MPMM_SPIN_WAIT)
	{
		prior = MPMM_ATOMIC_LOAD_ACQ_UPTR(head);
		mpmm_flist_node* ptr = (mpmm_flist_node*)(prior & ~chunk_size_mask);
		MPMM_UNLIKELY_IF(ptr == NULL)
			return NULL;
		desired = (size_t)ptr->next | (((prior & chunk_size_mask) + 1) & chunk_size_mask);
		MPMM_LIKELY_IF(MPMM_ATOMIC_CAS_WEAK_ACQ_UPTR(head, &prior, desired))
			return ptr;
	}
}

MPMM_ULTRAPURE MPMM_INLINE_ALWAYS static size_t mpmm_chunk_index_of(void* chunk)
{
	size_t mask = (size_t)chunk;
	mask >>= chunk_size_log2;
	return mask;
}

// ================================================================
//	BLOCK ALLOCATOR
// ================================================================

typedef struct mpmm_block_allocator
{
	MPMM_SHARED_ATTR struct mpmm_block_allocator* next;
	struct mpmm_tcache* owner;
	uint8_t* buffer;
	uint32_t free_count;
	uint8_t block_size_log2;
	uint8_t size_class;
	mpmm_atomic_bool linked;
	size_t free_map[MPMM_BLOCK_ALLOCATOR_MASK_COUNT / 2];
	MPMM_SHARED_ATTR mpmm_atomic_size_t marked_map[MPMM_BLOCK_ALLOCATOR_MASK_COUNT / 2];
} mpmm_block_allocator;

typedef struct mpmm_intrusive_block_allocator
{
	MPMM_SHARED_ATTR struct mpmm_intrusive_block_allocator* next;
	struct mpmm_tcache* owner;
	uint32_t free_count;
	uint32_t block_size;
	uint8_t size_class;
	mpmm_atomic_bool linked;
	MPMM_SHARED_ATTR size_t free_map[MPMM_BLOCK_ALLOCATOR_MASK_COUNT];
	MPMM_SHARED_ATTR mpmm_atomic_size_t marked_map[MPMM_BLOCK_ALLOCATOR_MASK_COUNT];
} mpmm_intrusive_block_allocator;

MPMM_ULTRAPURE MPMM_INLINE_ALWAYS static size_t mpmm_chunk_size_of(size_t size)
{
	size |= (size == 0);
	size *= MPMM_BLOCK_ALLOCATOR_MAX_CAPACITY;
	MPMM_UNLIKELY_IF(size > chunk_size)
		size = chunk_size;
	size = MPMM_POW2_ROUND(size);
	return size;
}

MPMM_PURE MPMM_INLINE_ALWAYS static uint_fast32_t mpmm_intrusive_block_allocator_index_of(void* buffer, size_t block_size, void* ptr)
{
	MPMM_INVARIANT(buffer != NULL);
	return (uint_fast32_t)(((size_t)((uint8_t*)ptr - (uint8_t*)buffer)) / block_size);
}

MPMM_PURE MPMM_INLINE_ALWAYS static uint_fast32_t mpmm_block_allocator_index_of(void* buffer, uint_fast8_t block_size_log2, void* ptr)
{
	MPMM_INVARIANT(buffer != NULL);
	return (uint_fast32_t)(((size_t)((uint8_t*)ptr - (uint8_t*)buffer)) >> block_size_log2);
}

MPMM_PURE MPMM_INLINE_ALWAYS static mpmm_bool mpmm_intrusive_block_allocator_owns(void* buffer, void* ptr, size_t block_size, size_t* free_map)
{
	MPMM_UNLIKELY_IF((uint8_t*)ptr < (uint8_t*)buffer || (uint8_t*)ptr >= (uint8_t*)buffer + mpmm_chunk_size_of(block_size))
		return 0;
	uint_fast32_t index = mpmm_intrusive_block_allocator_index_of(buffer, block_size, ptr);
	uint_fast32_t mask_index = index >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	uint_fast32_t bit_index = index & MPMM_BLOCK_MASK_MOD_MASK;
	return !MPMM_BT(free_map[mask_index], bit_index);
}

MPMM_PURE MPMM_INLINE_ALWAYS static mpmm_bool mpmm_block_allocator_owns(void* buffer, void* ptr, uint_fast8_t block_size_log2, size_t* free_map)
{
	MPMM_UNLIKELY_IF((uint8_t*)ptr < (uint8_t*)buffer || (uint8_t*)ptr >= (uint8_t*)buffer + mpmm_chunk_size_of((size_t)1 << block_size_log2))
		return 0;
	uint_fast32_t index = mpmm_block_allocator_index_of(buffer, block_size_log2, ptr);
	uint_fast32_t mask_index = index >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	uint_fast32_t bit_index = index & MPMM_BLOCK_MASK_MOD_MASK;
	return !MPMM_BT(free_map[mask_index], bit_index);
}

MPMM_INLINE_ALWAYS static void mpmm_block_allocator_init(mpmm_block_allocator* self, uint_fast8_t block_size_log2, uint_fast8_t sc, size_t chunk_size, struct mpmm_tcache* owner, void* buffer)
{
	MPMM_INVARIANT(chunk_size_log2 > block_size_log2);
	MPMM_INVARIANT(self != NULL);
	MPMM_INVARIANT(buffer != NULL);
	self->next = NULL;
	self->free_count = 1U << (chunk_size_log2 - block_size_log2);
	self->block_size_log2 = block_size_log2;
	self->owner = owner;
	self->buffer = (uint8_t*)buffer;
	self->linked = 1;
	(void)memset(self->free_map, 0xff, sizeof(self->free_map));
	(void)memset((void*)self->marked_map, 0, sizeof(self->marked_map));
}

MPMM_INLINE_ALWAYS static void mpmm_intrusive_block_allocator_init(mpmm_intrusive_block_allocator* self, uint_fast32_t block_size, uint_fast8_t sc, size_t chunk_size, struct mpmm_tcache* owner)
{
	MPMM_INVARIANT(self != NULL);
	self->next = NULL;
	uint_fast32_t reserved_count = (uint_fast32_t)MPMM_ALIGN_ROUND(sizeof(mpmm_intrusive_block_allocator), (size_t)block_size) / block_size;
	uint_fast32_t capacity = (uint_fast32_t)(chunk_size / block_size);
	self->free_count = capacity - reserved_count;
	self->block_size = block_size;
	self->owner = owner;
	self->linked = 1;
	(void)memset(self->free_map, 0, sizeof(self->free_map));
	(void)memset((void*)self->marked_map, 0, sizeof(self->marked_map));
	uint_fast32_t mask_count = capacity >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	uint_fast32_t bit_count = capacity & MPMM_BLOCK_MASK_MOD_MASK;
	MPMM_LIKELY_IF(mask_count != 0)
		(void)memset(self->free_map, 0xff, mask_count * sizeof(size_t));
	MPMM_LIKELY_IF(bit_count != 0)
		self->free_map[mask_count] = ((size_t)1 << bit_count) - (size_t)1;
	mask_count = reserved_count >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	bit_count = reserved_count & MPMM_BLOCK_MASK_MOD_MASK;
	MPMM_LIKELY_IF(mask_count != 0)
		(void)memset(self->free_map, 0, mask_count * sizeof(size_t));
	MPMM_LIKELY_IF(bit_count != 0)
		self->free_map[0] &= ~(((size_t)1 << bit_count) - (size_t)1);
}

MPMM_INLINE_NEVER static uint_fast32_t mpmm_generic_block_allocator_reclaim(size_t* free_map, mpmm_atomic_size_t* marked_map, size_t bitmask_count)
{
	size_t mask;
	uint_fast32_t i, freed_count;

	freed_count = 0;
	for (i = 0; i != bitmask_count; ++i)
	{
		MPMM_LIKELY_IF(MPMM_ATOMIC_LOAD_ACQ_UPTR(marked_map + i) != 0)
		{
			mask = MPMM_ATOMIC_SWAP_ACQ_UPTR(marked_map + i, 0);
			free_map[i] |= mask;
			freed_count += MPMM_POPCNT(mask);
		}
	}
	return freed_count;
}

MPMM_INLINE_ALWAYS static void* mpmm_block_allocator_malloc(mpmm_block_allocator* self)
{
	uint_fast32_t mask_index, bit_index, offset;
	for (mask_index = 0; mask_index != MPMM_BLOCK_ALLOCATOR_MASK_COUNT; ++mask_index)
	{
		MPMM_UNLIKELY_IF(self->free_map[mask_index] == 0)
			continue;
		bit_index = MPMM_CTZ(self->free_map[mask_index]);
		MPMM_BR(self->free_map[mask_index], bit_index);
		offset = (mask_index << MPMM_BLOCK_MASK_BIT_SIZE_LOG2) | bit_index;
		offset <<= self->block_size_log2;
		--self->free_count;
		MPMM_UNLIKELY_IF(self->free_count == 0)
		{
			MPMM_UNLIKELY_IF(self->next != NULL)
				MPMM_PREFETCH(self->next);
			self->free_count += mpmm_generic_block_allocator_reclaim(self->free_map, self->marked_map, MPMM_BLOCK_ALLOCATOR_MASK_COUNT);
		}
		return self->buffer + offset;
	}
	MPMM_UNREACHABLE;
}

MPMM_INLINE_ALWAYS static void* mpmm_intrusive_block_allocator_malloc(mpmm_intrusive_block_allocator* self)
{
	uint_fast32_t mask_index, bit_index, offset;
	for (mask_index = 0; mask_index != MPMM_BLOCK_ALLOCATOR_MASK_COUNT; ++mask_index)
	{
		MPMM_UNLIKELY_IF(self->free_map[mask_index] == 0)
			continue;
		bit_index = MPMM_CTZ(self->free_map[mask_index]);
		MPMM_BR(self->free_map[mask_index], bit_index);
		offset = (mask_index << MPMM_BLOCK_MASK_BIT_SIZE_LOG2) | bit_index;
		offset *= self->block_size;
		--self->free_count;
		MPMM_UNLIKELY_IF(self->free_count == 0)
		{
			MPMM_UNLIKELY_IF(self->next != NULL)
				MPMM_PREFETCH(self->next);
			self->free_count += mpmm_generic_block_allocator_reclaim(self->free_map, self->marked_map, MPMM_BLOCK_ALLOCATOR_MASK_COUNT);
		}
		return (uint8_t*)self + offset;
	}
	MPMM_UNREACHABLE;
}

MPMM_INLINE_NEVER static void mpmm_generic_block_allocator_recover(mpmm_atomic_bool* linked, mpmm_rlist* recovered, void* self)
{
	mpmm_flist_node* desired;
	MPMM_UNLIKELY_IF(MPMM_ATOMIC_TAS_ACQ(linked))
		return;
	desired = (mpmm_flist_node*)self;
	for (;; MPMM_SPIN_WAIT)
	{
		desired->next = (mpmm_flist_node*)MPMM_ATOMIC_LOAD_ACQ_PTR(recovered);
		MPMM_LIKELY_IF(MPMM_ATOMIC_WCAS_REL_PTR(recovered, &desired->next, desired))
			break;
	}
}

MPMM_INLINE_ALWAYS static void mpmm_intrusive_block_allocator_free(mpmm_intrusive_block_allocator* self, void* ptr)
{
	MPMM_INVARIANT(mpmm_intrusive_block_allocator_owns(self, ptr, self->block_size, self->free_map));
	uint_fast32_t index, mask_index, bit_index;
	++self->free_count;
	index = mpmm_intrusive_block_allocator_index_of(self, self->block_size, ptr);
	mask_index = index >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	bit_index = index & MPMM_BLOCK_MASK_MOD_MASK;
	MPMM_BS(self->free_map[mask_index], bit_index);
	MPMM_UNLIKELY_IF(MPMM_ATOMIC_TEST_ACQ(&self->linked))
		mpmm_generic_block_allocator_recover(&self->linked, self->owner->recovered + self->size_class, self);
}

MPMM_INLINE_ALWAYS static void mpmm_intrusive_block_allocator_free_shared(mpmm_intrusive_block_allocator* self, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	index = mpmm_intrusive_block_allocator_index_of(self, self->block_size, ptr);
	mask_index = index >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	bit_index = index & MPMM_BLOCK_MASK_MOD_MASK;
	MPMM_ATOMIC_BIT_SET_REL(self->marked_map + mask_index, bit_index);
	MPMM_UNLIKELY_IF(MPMM_ATOMIC_TEST_ACQ(&self->linked))
		mpmm_generic_block_allocator_recover(&self->linked, self->owner->recovered + self->size_class, self);
}

MPMM_INLINE_ALWAYS static void mpmm_block_allocator_free(mpmm_block_allocator* self, void* ptr)
{
	MPMM_INVARIANT(mpmm_block_allocator_owns(self, ptr, self->block_size_log2, self->free_map));
	uint_fast32_t index, mask_index, bit_index;
	++self->free_count;
	index = mpmm_block_allocator_index_of(self, self->block_size_log2, ptr);
	mask_index = index >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	bit_index = index & MPMM_BLOCK_MASK_MOD_MASK;
	MPMM_BS(self->free_map[mask_index], bit_index);
	MPMM_UNLIKELY_IF(MPMM_ATOMIC_TEST_ACQ(&self->linked))
		mpmm_generic_block_allocator_recover(&self->linked, self->owner->recovered + self->size_class, self);
}

MPMM_INLINE_ALWAYS static void mpmm_block_allocator_free_shared(mpmm_block_allocator* self, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	index = mpmm_block_allocator_index_of(self, self->block_size_log2, ptr);
	mask_index = index >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	bit_index = index & MPMM_BLOCK_MASK_MOD_MASK;
	MPMM_ATOMIC_BIT_SET_REL(self->marked_map + mask_index, bit_index);
	MPMM_UNLIKELY_IF(MPMM_ATOMIC_TEST_ACQ(&self->linked))
		mpmm_generic_block_allocator_recover(&self->linked, self->owner->recovered + self->size_class, self);
}

MPMM_INLINE_ALWAYS static mpmm_intrusive_block_allocator* mpmm_intrusive_block_allocator_allocator_of(void* ptr, size_t chunk_size)
{
	size_t mask = (size_t)ptr;
	mask = MPMM_ALIGN_FLOOR(mask, chunk_size);
	return (mpmm_intrusive_block_allocator*)mask;
}

// ================================================================
//	STATS
// ================================================================

typedef struct mpmm_shared_counter { MPMM_SHARED_ATTR mpmm_atomic_size_t value; } mpmm_shared_counter;

static mpmm_shared_counter used_memory;
static mpmm_shared_counter total_memory;

// ================================================================
//	PERSISTENT
// ================================================================

typedef struct persistent_node
{
	MPMM_SHARED_ATTR
	struct persistent_node* next;
	mpmm_atomic_size_t bump;
} persistent_node;

typedef MPMM_ATOMIC(persistent_node*) persistent_allocator;

MPMM_INLINE_ALWAYS static void* mpmm_persistent_node_malloc(persistent_node* self, size_t size)
{
	size_t prior = MPMM_ATOMIC_FAA_ACQ(&self->bump, size);
	MPMM_LIKELY_IF(prior + size <= chunk_size)
		return (uint8_t*)self + prior;
	(void)MPMM_ATOMIC_FAS_REL(&self->bump, size);
	return NULL;
}

static persistent_allocator internal_persistent_allocator;
static persistent_allocator public_persistent_allocator;

MPMM_ATTR void* MPMM_CALL mpmm_persistent_malloc_impl(persistent_allocator* allocator, size_t size)
{
	void* r;
	persistent_node* n;
	persistent_node* prior;
	persistent_node* current;
	size_t offset;

	MPMM_UNLIKELY_IF(size >= chunk_size)
		return mpmm_lcache_malloc(MPMM_ALIGN_ROUND(size, chunk_size), MPMM_ENABLE_FALLBACK);
	current = (persistent_node*)MPMM_ATOMIC_LOAD_ACQ_PTR(allocator);
	do
	{
		prior = current;
		for (n = prior; n != NULL; n = n->next)
		{
			r = mpmm_persistent_node_malloc(n, size);
			MPMM_LIKELY_IF(r != NULL)
				return r;
		}
		current = (persistent_node*)MPMM_ATOMIC_LOAD_ACQ_PTR(allocator);
	} while (prior != current);
	n = (persistent_node*)mpmm_lcache_malloc(chunk_size, MPMM_ENABLE_FALLBACK);
	MPMM_UNLIKELY_IF(n == NULL)
		return NULL;
	offset = MPMM_ALIGN_ROUND(sizeof(persistent_node), MPMM_CACHE_LINE_SIZE);
	r = (uint8_t*)n + offset;
	offset += size;
	n->bump = offset;
	for (;; MPMM_SPIN_WAIT)
	{
		prior = (persistent_node*)MPMM_ATOMIC_LOAD_ACQ_PTR(allocator);
		n->next = prior;
		MPMM_LIKELY_IF(MPMM_ATOMIC_WCAS_ACQ_PTR(allocator, &prior, n))
			return r;
	}
}

MPMM_ATTR void MPMM_CALL mpmm_persistent_cleanup_impl(persistent_allocator* allocator)
{
	persistent_node* next;
	persistent_node* n;
	n = (persistent_node*)MPMM_ATOMIC_SWAP_ACQ_PTR(allocator, NULL);
	for (; n != NULL; n = next)
	{
		next = n->next;
		backend_free(n, chunk_size);
	}
}

#ifdef MPMM_64BIT
#define MPMM_TRIE_ROOT_SIZE 256

typedef uint8_t* mpmm_trie_leaf;
typedef MPMM_ATOMIC(mpmm_trie_leaf)* mpmm_trie_branch;
typedef MPMM_ATOMIC(mpmm_trie_branch) mpmm_trie_root;
static size_t branch_size;
static size_t branch_mask;
static size_t leaf_size;
static size_t leaf_mask;
static uint8_t leaf_log2;
static uint8_t branch_log2;

static void* mpmm_trie_find(mpmm_trie_root* root, size_t key, uint_fast8_t value_size_log2)
{
	uint_fast8_t root_index;
	size_t branch_index, leaf_index;
	mpmm_trie_branch branch;
	mpmm_trie_leaf leaf;
	size_t offset;

	leaf_index = key & leaf_mask;
	key >>= leaf_log2;
	branch_index = key & branch_mask;
	key >>= branch_log2;
	root_index = (uint_fast8_t)key;

	branch = (mpmm_trie_branch)MPMM_ATOMIC_LOAD_ACQ_PTR(root + root_index);
	MPMM_UNLIKELY_IF(branch == NULL)
		return NULL;
	branch += branch_index;
	leaf = (mpmm_trie_leaf)MPMM_ATOMIC_LOAD_ACQ_PTR(branch);
	MPMM_UNLIKELY_IF(leaf == NULL)
		return NULL;
	offset = leaf_index << value_size_log2;
	MPMM_INVARIANT(offset + (1ULL << value_size_log2) <= (leaf_size << value_size_log2));
	return leaf + offset;
}

static void* mpmm_trie_insert(mpmm_trie_root* root, size_t key, uint_fast8_t value_size_log2)
{
	uint_fast8_t root_index;
	size_t branch_index, leaf_index;
	mpmm_trie_branch branch;
	mpmm_trie_branch new_branch;
	mpmm_trie_leaf leaf;
	mpmm_trie_leaf new_leaf;
	size_t offset;
	size_t real_branch_size = branch_size << MPMM_POINTER_SIZE_LOG2;
	size_t real_leaf_size = leaf_size << value_size_log2;

	leaf_index = key & leaf_mask;
	key >>= leaf_log2;
	branch_index = key & branch_mask;
	key >>= branch_log2;
	root_index = (uint_fast8_t)key;

	root += root_index;
	for (;; MPMM_SPIN_WAIT)
	{
		branch = (mpmm_trie_branch)MPMM_ATOMIC_LOAD_ACQ_PTR(root);
		MPMM_LIKELY_IF(branch != NULL)
			break;
		new_branch = (mpmm_trie_branch)mpmm_lcache_malloc(real_branch_size, MPMM_ENABLE_FALLBACK);
		MPMM_UNLIKELY_IF(new_branch == NULL)
			return NULL;
		MPMM_LIKELY_IF(MPMM_ATOMIC_CAS_REL_PTR(root, &branch, new_branch))
		{
			branch = new_branch;
			(void)memset((void*)branch, 0, real_branch_size);
			break;
		}
		mpmm_lcache_free((void*)new_branch, real_branch_size);
	}
	branch += branch_index;
	for (;; MPMM_SPIN_WAIT)
	{
		leaf = (mpmm_trie_leaf)MPMM_ATOMIC_LOAD_ACQ_PTR(branch);
		MPMM_LIKELY_IF(leaf != NULL)
			break;
		new_leaf = (mpmm_trie_leaf)mpmm_lcache_malloc(real_leaf_size, MPMM_ENABLE_FALLBACK);
		MPMM_UNLIKELY_IF(new_leaf == NULL)
			return NULL;
		MPMM_LIKELY_IF(MPMM_ATOMIC_CAS_REL_PTR(branch, &leaf, new_leaf))
		{
			leaf = new_leaf;
			break;
		}
		mpmm_lcache_free(new_leaf, real_leaf_size);
	}
	offset = leaf_index << value_size_log2;
	MPMM_INVARIANT(offset + (1ULL << value_size_log2) <= real_leaf_size);
	leaf += offset;
	return leaf;
}
#endif

// ================================================================
//	LARGE CACHE
// ================================================================

typedef struct mpmm_lcache_bin
{
	MPMM_SHARED_ATTR mpmm_chunk_list list;
} mpmm_lcache_bin;

#ifdef MPMM_32BIT
#ifdef MPMM_DEBUG
static size_t lcache_bin_count;
#endif
static mpmm_lcache_bin* lcache_bins;
#else
static mpmm_trie_root lcache_bin_roots[MPMM_TRIE_ROOT_SIZE];
#endif

MPMM_INLINE_ALWAYS static void mpmm_lcache_init()
{
#ifdef MPMM_32BIT
#ifndef MPMM_DEBUG
	size_t lcache_bin_count;
#endif
	lcache_bin_count = 1 << (32 - chunk_size_log2);
	lcache_bins = (mpmm_lcache_bin*)mpmm_persistent_malloc_impl(&internal_persistent_allocator, lcache_bin_count * sizeof(mpmm_lcache_bin));
	MPMM_INVARIANT(lcache_bins != NULL);
#else
	uint_fast8_t n = 64 - chunk_size_log2;
	leaf_log2 = chunk_size_log2 - 4;
	branch_log2 = n - chunk_size_log2 - 4;
	branch_size = 1ULL << branch_log2;
	leaf_size = 1ULL << leaf_log2;
	branch_mask = branch_size - 1;
	leaf_mask = leaf_size - 1;
	MPMM_INVARIANT(leaf_log2 + branch_log2 + 8 == (64 - chunk_size_log2));
#endif
}

MPMM_INLINE_ALWAYS static mpmm_chunk_list* mpmm_lcache_find_bin(size_t size)
{
	size >>= chunk_size_log2;
	size -= size != 0;
#ifdef MPMM_32BIT
	return &lcache_bins[size].list;
#else
	return (mpmm_chunk_list*)mpmm_trie_find(lcache_bin_roots, size, MPMM_LOG2(sizeof(mpmm_chunk_list)));
#endif
}

MPMM_INLINE_ALWAYS static mpmm_chunk_list* mpmm_lcache_insert_bin(size_t size)
{
#ifdef MPMM_32BIT
	return mpmm_lcache_find_bin(size);
#else
	size >>= chunk_size_log2;
	size -= size != 0;
	return (mpmm_chunk_list*)mpmm_trie_insert(lcache_bin_roots, size, MPMM_LOG2(sizeof(mpmm_chunk_list)));
#endif
}

// ================================================================
//	THREAD CACHE
// ================================================================

#ifdef MPMM_32BIT
static mpmm_block_allocator* tcache_lookup;
#else
static mpmm_trie_root tcache_lookup_roots[MPMM_TRIE_ROOT_SIZE];
#endif

#ifdef MPMM_32BIT
MPMM_INLINE_ALWAYS static void mpmm_tcache_lookup_init()
{
	size_t k = 1U << (32 - chunk_size_log2);
	tcache_lookup = (mpmm_block_allocator*)mpmm_persistent_malloc_impl(&internal_persistent_allocator, sizeof(mpmm_block_allocator) * k);
}
#endif

MPMM_TLS static mpmm_tcache this_thread_tcache;

MPMM_INLINE_ALWAYS static mpmm_block_allocator* mpmm_tcache_find_allocator(void* buffer)
{
	size_t id = mpmm_chunk_index_of(buffer);
#ifdef MPMM_32BIT
	MPMM_INVARIANT(tcache_lookup != NULL);
	return tcache_lookup + id;
#else
	return (mpmm_block_allocator*)mpmm_trie_find(lcache_bin_roots, id, MPMM_LOG2(sizeof(mpmm_block_allocator)));
#endif
}

MPMM_INLINE_ALWAYS static mpmm_block_allocator* mpmm_tcache_insert_allocator(void* buffer)
{
#ifdef MPMM_32BIT
	return mpmm_tcache_find_allocator(buffer);
#else
	size_t id = mpmm_chunk_index_of(buffer);
	size_t object_size = sizeof(mpmm_block_allocator);
	uint_fast8_t object_size_log2 = MPMM_LOG2(object_size);
	return (mpmm_block_allocator*)mpmm_trie_insert(lcache_bin_roots, id, object_size_log2);
#endif
}

MPMM_INLINE_ALWAYS static mpmm_block_allocator* mpmm_tcache_block_allocator_of(void* ptr)
{
	size_t mask = (size_t)ptr;
	mask &= ~chunk_size_mask;
	return mpmm_tcache_find_allocator((void*)mask);
}

MPMM_PURE MPMM_INLINE_ALWAYS static uint_fast32_t mpmm_tcache_size_class(size_t size)
{
	uint_fast8_t log2 = MPMM_LOG2(size);
	uint_fast8_t limit = MPMM_SIZE_MAP_SIZE;
	MPMM_UNLIKELY_IF(log2 >= limit)
		return MPMM_LOG2_32((uint32_t)size) - 12;
	const uint_fast32_t* map = MPMM_SIZE_CLASS_LOOKUP[log2];
	uint_fast32_t map_size = MPMM_SIZE_MAP_SIZES[log2];
	uint_fast32_t offset = MPMM_SIZE_MAP_OFFSETS[log2];
	uint_fast8_t i = 0;
	for (; i != map_size; ++i)
		MPMM_LIKELY_IF(map[i] >= size)
			return offset + i;
	MPMM_UNREACHABLE;
}

MPMM_INLINE_ALWAYS static void* mpmm_tcache_malloc_small_slow(mpmm_tcache* tcache, size_t size, uint_fast8_t sc)
{
	void* r;
	size_t k;
	mpmm_intrusive_block_allocator* allocator;
	mpmm_intrusive_block_allocator** bin;

	k = mpmm_chunk_size_of(size);
	allocator = (mpmm_intrusive_block_allocator*)mpmm_malloc(k);
	MPMM_UNLIKELY_IF(allocator == NULL)
		return NULL;
	mpmm_intrusive_block_allocator_init(allocator, (uint_fast32_t)size, sc, k, &this_thread_tcache);
	r = mpmm_intrusive_block_allocator_malloc(allocator);
	bin = tcache->bins + sc;
	allocator->next = *bin;
	*bin = allocator;
	return r;
}

MPMM_INLINE_ALWAYS static void* mpmm_tcache_malloc_large_slow(mpmm_tcache* tcache, size_t size, uint_fast8_t sc)
{
	void* r;
	void* buffer;
	size_t k;
	mpmm_block_allocator* allocator;
	mpmm_block_allocator** bin;

	k = mpmm_chunk_size_of(size);
	buffer = mpmm_lcache_malloc(chunk_size, MPMM_ENABLE_FALLBACK);
	MPMM_UNLIKELY_IF(buffer == NULL)
		return NULL;
	allocator = mpmm_tcache_insert_allocator(buffer);
	MPMM_UNLIKELY_IF(allocator == NULL)
		return NULL;
	mpmm_block_allocator_init(allocator, MPMM_LOG2(size), sc, k, &this_thread_tcache, buffer);
	r = mpmm_block_allocator_malloc(allocator);
	bin = tcache->bins_large + sc;
	allocator->next = *bin;
	*bin = allocator;
	return r;
}

MPMM_INLINE_ALWAYS static void* mpmm_tcache_malloc_small_fast(mpmm_tcache* tcache, size_t size, uint_fast8_t sc, uint_fast64_t flags)
{
	void* r;
	mpmm_intrusive_block_allocator** bin;
	mpmm_rlist* recover_list;
	mpmm_intrusive_block_allocator* allocator;

	bin = tcache->bins + sc;
	recover_list = tcache->recovered + sc;
	allocator = (mpmm_intrusive_block_allocator*)*bin;
	MPMM_UNLIKELY_IF(allocator == NULL)
	{
		allocator = (mpmm_intrusive_block_allocator*)MPMM_ATOMIC_SWAP_ACQ_PTR(recover_list, NULL);
		MPMM_UNLIKELY_IF(allocator == NULL)
			return (flags & MPMM_ENABLE_FALLBACK) ? mpmm_tcache_malloc_small_slow(tcache, size, sc) : NULL;
		*bin = (mpmm_intrusive_block_allocator*)allocator;
	}
	r = mpmm_intrusive_block_allocator_malloc(allocator);
	MPMM_INVARIANT(r != NULL);
	MPMM_UNLIKELY_IF(allocator->free_count == 0)
	{
		MPMM_ATOMIC_CLEAR_REL(&allocator->linked);
		*bin = (*bin)->next;
		allocator->next = NULL;
	}
	return r;
}

MPMM_INLINE_ALWAYS static void* mpmm_tcache_malloc_large_fast(mpmm_tcache* tcache, size_t size, uint_fast8_t sc, uint_fast64_t flags)
{
	void* r;
	mpmm_block_allocator** bin;
	mpmm_rlist* recover_list;
	mpmm_block_allocator* allocator;
	
	bin = tcache->bins_large + sc;
	recover_list = tcache->recovered_large + sc;
	allocator = (mpmm_block_allocator*)*bin;
	MPMM_UNLIKELY_IF(allocator == NULL)
	{
		allocator = (mpmm_block_allocator*)MPMM_ATOMIC_SWAP_ACQ_PTR(recover_list, NULL);
		MPMM_UNLIKELY_IF(allocator == NULL)
			return (flags & MPMM_ENABLE_FALLBACK) ? mpmm_tcache_malloc_large_slow(tcache, size, sc) : NULL;
		*bin = (mpmm_block_allocator*)allocator;
	}
	r = mpmm_block_allocator_malloc(allocator);
	MPMM_INVARIANT(r != NULL);
	MPMM_UNLIKELY_IF(allocator->free_count == 0)
	{
		MPMM_ATOMIC_CLEAR_REL(&allocator->linked);
		*bin = (*bin)->next;
		allocator->next = NULL;
	}
	return r;
}

// ================================================================
//	DEBUG API
// ================================================================

#ifdef MPMM_DEBUG
#include <stdio.h>
static void mpmm_default_debugger_message_callback(void* context, const char* message, size_t size)
{
	MPMM_INVARIANT(message != NULL);
	(void)fwrite(message, 1, size, stdout);
}

static void mpmm_default_debugger_warning_callback(void* context, const char* message, size_t size)
{
	MPMM_INVARIANT(message != NULL);
	(void)fwrite(message, 1, size, stdout);
}

static void mpmm_default_debugger_error_callback(void* context, const char* message, size_t size)
{
	MPMM_INVARIANT(message != NULL);
	(void)fwrite(message, 1, size, stderr);
}

MPMM_INLINE_ALWAYS static void mpmm_init_redzone(void* buffer, size_t size)
{
	buffer = (uint8_t*)buffer + size;
	(void)memset(buffer, 0xab, MPMM_REDZONE_SIZE);
}

MPMM_INLINE_ALWAYS static mpmm_bool mpmm_check_redzone(const void* buffer, size_t size)
{
	const size_t count = MPMM_REDZONE_SIZE >> MPMM_POINTER_SIZE_LOG2;
	const size_t* ptr;
	size_t expected;
	size_t i;

	buffer = (const uint8_t*)buffer + size;
	ptr = (const size_t*)buffer;
	(void)memset(&expected, MPMM_REDZONE_VALUE, sizeof(expected));
	for (i = 0; i != count; ++i)
		MPMM_UNLIKELY_IF(ptr[i] != expected)
			return 0;
	return 1;
}

#endif

// ================================================================
//	MAIN API
// ================================================================

MPMM_EXTERN_C_BEGIN
MPMM_ATTR void MPMM_CALL mpmm_init_info_default(mpmm_init_options* out_options)
{
	out_options->expected_concurrency = 0;
	out_options->backend = NULL;
}

MPMM_ATTR void MPMM_CALL mpmm_trim_options_default(mpmm_trim_options* out_options)
{
	out_options->trim_limit = SIZE_MAX;
}

MPMM_ATTR void MPMM_CALL mpmm_debugger_options_default(mpmm_debugger_options* out_options)
{
	out_options->context = NULL;
#ifdef MPMM_DEBUG
	out_options->message = mpmm_default_debugger_message_callback;
	out_options->warning = mpmm_default_debugger_warning_callback;
	out_options->error = mpmm_default_debugger_error_callback;
#endif
}

MPMM_ATTR size_t MPMM_CALL mpmm_backend_required_alignment()
{
	return chunk_size;
}

MPMM_ATTR void MPMM_CALL mpmm_init(const mpmm_init_options* options)
{
	mpmm_sys_init();
	MPMM_UNLIKELY_IF(options != NULL)
	{
		expected_concurrency = options->expected_concurrency;
		MPMM_INVARIANT(expected_concurrency < chunk_size);
		MPMM_UNLIKELY_IF(options->backend != NULL)
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
	mpmm_lcache_init();
#ifdef MPMM_32BIT
	mpmm_tcache_lookup_init();
#else
	mpmm_init_flag = 1;
#endif
}

MPMM_ATTR mpmm_bool MPMM_CALL mpmm_is_initialized()
{
#ifdef MPMM_32BIT
	return lcache_bins != NULL;
#else
	return mpmm_init_flag;
#endif
}

MPMM_ATTR void MPMM_CALL mpmm_cleanup()
{
	mpmm_persistent_cleanup_impl(&public_persistent_allocator);
#ifdef MPMM_64BIT
	mpmm_init_flag = 0;
#endif
}

MPMM_ATTR void MPMM_CALL mpmm_thread_init()
{
	uint8_t* buffer = (uint8_t*)mpmm_persistent_malloc_impl(&internal_persistent_allocator, tcache_buffer_size);
	(void)memset(buffer, 0, tcache_buffer_size);
	this_thread_tcache.bins = (mpmm_intrusive_block_allocator**)buffer;
	buffer += tcache_small_bin_buffer_size;
	this_thread_tcache.recovered = (mpmm_rlist*)buffer;
	buffer += tcache_small_bin_buffer_size;
	this_thread_tcache.bins_large = (mpmm_block_allocator**)buffer;
	buffer += tcache_large_bin_buffer_size;
	this_thread_tcache.recovered_large = (mpmm_rlist*)buffer;
}

MPMM_ATTR void MPMM_CALL mpmm_thread_cleanup()
{

}

MPMM_ATTR void MPMM_CALL mpmm_stats(mpmm_mem_stats* out_stats)
{
}

MPMM_ATTR void MPMM_CALL mpmm_params(mpmm_global_params* out_params)
{
	out_params->page_size = page_size;
	out_params->chunk_size = chunk_size;
	out_params->expected_concurrency = expected_concurrency;
}

MPMM_ATTR void* MPMM_CALL mpmm_malloc(size_t size)
{
	void* r;
	size = mpmm_round_size(size);
	MPMM_LIKELY_IF(size <= mpmm_tcache_max_size())
		r = mpmm_tcache_malloc(size, MPMM_ENABLE_FALLBACK);
	else
		r = mpmm_lcache_malloc(size, MPMM_ENABLE_FALLBACK);
	return r;
}

MPMM_ATTR mpmm_bool MPMM_CALL mpmm_resize(void* ptr, size_t old_size, size_t new_size)
{
	MPMM_INVARIANT(ptr != NULL);
	return mpmm_round_size(old_size) == mpmm_round_size(new_size);
}

MPMM_ATTR void* MPMM_CALL mpmm_realloc(void* ptr, size_t old_size, size_t new_size)
{
	MPMM_INVARIANT(ptr != NULL);
	MPMM_UNLIKELY_IF(mpmm_resize(ptr, old_size, new_size))
		return ptr;
	void* r = mpmm_malloc(new_size);
	MPMM_LIKELY_IF(r != NULL)
	{
		(void)memcpy(r, ptr, old_size);
		mpmm_free(ptr, old_size);
	}
	return r;
}

MPMM_ATTR void MPMM_CALL mpmm_free(void* ptr, size_t size)
{
	MPMM_INVARIANT(ptr != NULL);
	MPMM_LIKELY_IF(size < mpmm_tcache_max_size())
		return mpmm_tcache_free(ptr, size);
	return mpmm_lcache_free(ptr, size);
}

MPMM_ATTR size_t MPMM_CALL mpmm_round_size(size_t size)
{
	MPMM_LIKELY_IF(size < mpmm_tcache_max_size())
		return mpmm_tcache_round_size(size);
	return mpmm_lcache_round_size(size);
}

MPMM_ATTR size_t MPMM_CALL mpmm_purge(mpmm_flags flags, void* param)
{
	return 0;
}

MPMM_ATTR size_t MPMM_CALL mpmm_trim(const mpmm_trim_options* options)
{
	return 0;
}

MPMM_ATTR void* MPMM_CALL mpmm_tcache_malloc(size_t size, mpmm_flags flags)
{
	void* r;
	uint_fast8_t sc;
	sc = mpmm_tcache_size_class(size);
	if (size <= page_size)
		r = mpmm_tcache_malloc_small_fast(&this_thread_tcache, size, sc, flags);
	else
		r = mpmm_tcache_malloc_large_fast(&this_thread_tcache, size, sc, flags);
	MPMM_DEBUG_JUNK_FILL(r, size);
	return r;
}

MPMM_ATTR void MPMM_CALL mpmm_tcache_free(void* ptr, size_t size)
{
	mpmm_intrusive_block_allocator* intrusive_allocator;
	mpmm_block_allocator* allocator;

	size_t k = mpmm_chunk_size_of(size);
	MPMM_LIKELY_IF(size <= page_size)
	{
		intrusive_allocator = mpmm_intrusive_block_allocator_allocator_of(ptr, k);
		MPMM_LIKELY_IF(intrusive_allocator->owner == &this_thread_tcache)
			mpmm_intrusive_block_allocator_free(intrusive_allocator, ptr);
		else
			mpmm_intrusive_block_allocator_free_shared(intrusive_allocator, ptr);
	}
	else
	{
		allocator = mpmm_tcache_block_allocator_of(ptr);
		MPMM_LIKELY_IF(allocator->owner == &this_thread_tcache)
			mpmm_block_allocator_free(allocator, ptr);
		else
			mpmm_block_allocator_free_shared(allocator, ptr);
	}
}

MPMM_ATTR size_t MPMM_CALL mpmm_tcache_round_size(size_t size)
{
	MPMM_INVARIANT(size <= chunk_size / 2);
	MPMM_UNLIKELY_IF(size >= 4096)
		return MPMM_POW2_ROUND(size);
	uint_fast8_t log2 = MPMM_LOG2(size);
	const uint_fast8_t limit = MPMM_SIZE_MAP_SIZE;
	MPMM_INVARIANT(log2 < limit);
	const uint_fast32_t* map = MPMM_SIZE_CLASS_LOOKUP[log2];
	const uint_fast8_t map_size = MPMM_SIZE_MAP_SIZES[log2];
	uint_fast8_t i = 0;
	for (; i != map_size; ++i)
		MPMM_LIKELY_IF(map[i] >= size)
		return map[i];
	MPMM_UNREACHABLE;
}

MPMM_ATTR size_t MPMM_CALL mpmm_tcache_flush(mpmm_flags flags, void* param)
{
	return 0;
}

MPMM_ATTR size_t MPMM_CALL mpmm_tcache_min_size() { return 1; }
MPMM_ATTR size_t MPMM_CALL mpmm_tcache_max_size() { return chunk_size / 2; }

MPMM_ATTR void* MPMM_CALL mpmm_lcache_malloc(size_t size, mpmm_flags flags)
{
	void* r = NULL;
	mpmm_chunk_list* bin = mpmm_lcache_find_bin(size);
	MPMM_LIKELY_IF(bin != NULL)
		r = mpmm_chunk_list_pop(bin);
	MPMM_UNLIKELY_IF(r == NULL && (flags & MPMM_ENABLE_FALLBACK))
		r = backend_malloc(size);
	MPMM_DEBUG_JUNK_FILL(r, size);
	return r;
}

MPMM_ATTR void MPMM_CALL mpmm_lcache_free(void* ptr, size_t size)
{
	mpmm_chunk_list* bin = mpmm_lcache_insert_bin(size);
	MPMM_INVARIANT(bin != NULL);
	mpmm_chunk_list_push(bin, ptr);
}

MPMM_ATTR size_t MPMM_CALL mpmm_lcache_round_size(size_t size)
{
	return MPMM_ALIGN_ROUND(size, chunk_size);
}

MPMM_ATTR size_t MPMM_CALL mpmm_lcache_flush(mpmm_flags flags, void* param)
{
	return 0;
}

MPMM_ATTR size_t MPMM_CALL mpmm_lcache_min_size() { return chunk_size; }
MPMM_ATTR size_t MPMM_CALL mpmm_lcache_max_size() { return SIZE_MAX; }

MPMM_ATTR void* MPMM_CALL mpmm_persistent_malloc(size_t size)
{
	return mpmm_persistent_malloc_impl(&internal_persistent_allocator, size);
}

MPMM_ATTR void MPMM_CALL mpmm_persistent_cleanup()
{
	mpmm_persistent_cleanup_impl(&public_persistent_allocator);
}

MPMM_ATTR void* MPMM_CALL mpmm_backend_malloc(size_t size)
{
	MPMM_INVARIANT(backend_malloc != NULL);
	return backend_malloc(size);
}

MPMM_ATTR mpmm_bool MPMM_CALL mpmm_backend_resize(void* ptr, size_t old_size, size_t new_size)
{
	MPMM_INVARIANT(backend_resize != NULL);
	return backend_resize(ptr, old_size, new_size);
}

MPMM_ATTR void MPMM_CALL mpmm_backend_free(void* ptr, size_t size)
{
	MPMM_INVARIANT(backend_free != NULL);
	backend_free(ptr, size);
}

MPMM_ATTR void MPMM_CALL mpmm_backend_purge(void* ptr, size_t size)
{
	MPMM_INVARIANT(backend_purge != NULL);
	backend_purge(ptr, size);
}

MPMM_ATTR void MPMM_CALL mpmm_debugger_init(const mpmm_debugger_options* options)
{
#ifdef MPMM_DEBUG
	(void)memcpy(&debugger, options, sizeof(mpmm_debugger_options));
#endif
}

MPMM_ATTR mpmm_bool MPMM_CALL mpmm_debugger_enabled()
{
#ifdef MPMM_DEBUG
	return 1;
#else
	return 0;
#endif
}

MPMM_ATTR void MPMM_CALL mpmm_debugger_message(const char* message, size_t size)
{
#ifdef MPMM_DEBUG
	debugger.message(debugger.context, message, size);
#endif
}

MPMM_ATTR void MPMM_CALL mpmm_debugger_warning(const char* message, size_t size)
{
#ifdef MPMM_DEBUG
	debugger.warning(debugger.context, message, size);
#endif
}

MPMM_ATTR void MPMM_CALL mpmm_debugger_error(const char* message, size_t size)
{
#ifdef MPMM_DEBUG
	debugger.error(debugger.context, message, size);
#endif
}
MPMM_EXTERN_C_END
#endif
#endif