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
typedef enum mpmm_malloc_flags
{
	MPMM_ENABLE_FALLBACK = 1,
} mpmm_malloc_flags;

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
	size_t max_concurrency;
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
	size_t max_concurrency;
} mpmm_global_params;

MPMM_ATTR void					MPMM_CALL mpmm_init_info_default(mpmm_init_options* out_options);
MPMM_ATTR void					MPMM_CALL mpmm_trim_options_default(mpmm_trim_options* out_options);
MPMM_ATTR void					MPMM_CALL mpmm_debugger_options_default(mpmm_debugger_options* out_options);

MPMM_ATTR void					MPMM_CALL mpmm_init(const mpmm_init_options* options);
MPMM_ATTR mpmm_bool				MPMM_CALL mpmm_is_initialized();
MPMM_ATTR void					MPMM_CALL mpmm_reset();

MPMM_ATTR void					MPMM_CALL mpmm_stats(mpmm_mem_stats* out_stats);
MPMM_ATTR void					MPMM_CALL mpmm_params(mpmm_global_params* out_params);

MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_malloc(size_t size);
MPMM_ATTR mpmm_bool				MPMM_CALL mpmm_resize(void* ptr, size_t old_size, size_t new_size);
MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_realloc(void* ptr, size_t old_size, size_t new_size);
MPMM_ATTR void					MPMM_CALL mpmm_free(void* ptr, size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_round_size(size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_purge(uint64_t flags, void* param);
MPMM_ATTR size_t				MPMM_CALL mpmm_trim(const mpmm_trim_options* options);

MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_tcache_malloc(size_t size, uint64_t flags);
MPMM_ATTR void					MPMM_CALL mpmm_tcache_free(void* ptr, size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_tcache_round_size(size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_tcache_flush(uint64_t flags, void* param);
MPMM_ATTR size_t				MPMM_CALL mpmm_tcache_min_size();
MPMM_ATTR size_t				MPMM_CALL mpmm_tcache_max_size();

MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_lcache_malloc(size_t size, uint64_t flags);
MPMM_ATTR void					MPMM_CALL mpmm_lcache_free(void* ptr, size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_lcache_round_size(size_t size);
MPMM_ATTR size_t				MPMM_CALL mpmm_lcache_flush(uint64_t flags, void* param);
MPMM_ATTR size_t				MPMM_CALL mpmm_lcache_min_size();
MPMM_ATTR size_t				MPMM_CALL mpmm_lcache_max_size();

MPMM_NODISCARD MPMM_ATTR void*	MPMM_CALL mpmm_persistent_malloc(size_t size);
MPMM_ATTR void					MPMM_CALL mpmm_persistent_reset();

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
	MPMM_ATTR void			MPMM_CALL reset() noexcept { mpmm_reset(); }
	MPMM_ATTR memory_stats	MPMM_CALL stats() noexcept { mpmm_mem_stats r; mpmm_stats(&r); return r; }
	MPMM_ATTR void*			MPMM_CALL malloc(size_t size) noexcept { return mpmm_malloc(size); }
	MPMM_ATTR bool			MPMM_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept { return mpmm_resize(ptr, old_size, new_size); }
	MPMM_ATTR void*			MPMM_CALL realloc(void* ptr, size_t old_size, size_t new_size) noexcept { return mpmm_realloc(ptr, old_size, new_size); }
	MPMM_ATTR void			MPMM_CALL free(void* ptr, size_t size) noexcept { mpmm_free(ptr, size); }
	MPMM_ATTR size_t		MPMM_CALL round_size(size_t size) noexcept { return mpmm_round_size(size); }
	MPMM_ATTR size_t		MPMM_CALL purge(uint64_t flags, void* param) noexcept { return mpmm_purge(flags, param); }
	MPMM_ATTR size_t		MPMM_CALL trim(const trim_options* options) noexcept { return mpmm_trim((const mpmm_trim_options*)options); }

	namespace thread_cache
	{
		MPMM_ATTR void*		MPMM_CALL malloc(size_t size, uint64_t flags) noexcept { return mpmm_tcache_malloc(size, flags); }
		MPMM_ATTR void		MPMM_CALL free(void* ptr, size_t size) noexcept { mpmm_tcache_free(ptr, size); }
		MPMM_ATTR size_t	MPMM_CALL round_size(size_t size) noexcept { return mpmm_tcache_round_size(size); }
		MPMM_ATTR size_t	MPMM_CALL flush(uint64_t flags, void* param) noexcept { return mpmm_tcache_flush(flags, param); }
		MPMM_ATTR size_t	MPMM_CALL min_size() noexcept { return mpmm_tcache_min_size(); }
		MPMM_ATTR size_t	MPMM_CALL max_size() noexcept { return mpmm_tcache_max_size(); }
	}

	namespace large_cache
	{
		MPMM_ATTR void*		MPMM_CALL malloc(size_t size, uint64_t flags) noexcept { return mpmm_lcache_malloc(size, flags); }
		MPMM_ATTR void		MPMM_CALL free(void* ptr, size_t size) noexcept { mpmm_lcache_free(ptr, size); }
		MPMM_ATTR size_t	MPMM_CALL round_size(size_t size) noexcept { return mpmm_lcache_round_size(size); }
		MPMM_ATTR size_t	MPMM_CALL flush(uint64_t flags, void* param) noexcept { return mpmm_lcache_flush(flags, param); }
		MPMM_ATTR size_t	MPMM_CALL min_size() noexcept { return mpmm_lcache_min_size(); }
		MPMM_ATTR size_t	MPMM_CALL max_size() noexcept { return mpmm_lcache_max_size(); }
	}

	namespace persistent
	{
		MPMM_ATTR void*		MPMM_CALL malloc(size_t size) noexcept { return mpmm_persistent_malloc(size); }
		MPMM_ATTR void		MPMM_CALL reset() noexcept { mpmm_persistent_reset(); }
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
#include <stdatomic.h>
#include <stdalign.h>

#if UINT32_MAX == UINTPTR_MAX
#define MPMM_32BIT
#else
#define MPMM_64BIT
#error "MPMM: 64-BIT PROGRAMS ARE CURRENTLY NOT SUPPORTED."
#endif

#if !defined(MPMM_DEBUG) && (defined(_DEBUG) || !defined(NDEBUG))
#define MPMM_DEBUG
#endif

#ifndef MPMM_JUNK_VALUE
#define MPMM_JUNK_VALUE 0xcd
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

#if defined(__clang__) || defined(__GNUC__)
#if defined(__x86_64__) || defined(__i386__)
#define MPMM_SPIN_WAIT __builtin_ia32_pause()
#elif defined(__arm__)
#define MPMM_SPIN_WAIT __yield()
#endif
#define MPMM_PREFETCH(PTR) __builtin_prefetch((PTR), 1, 3)
#define MPMM_EXPECT(CONDITION, VALUE) __builtin_expect((CONDITION), (VALUE))
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
#include <intrin.h>
#if defined(__x86_64__) || defined(__i386__)
#define MPMM_SPIN_WAIT _mm_pause()
#define MPMM_PREFETCH(PTR) _mm_prefetch((PTR), _MM_HINT_T0)
#elif defined(__arm__)
#define MPMM_SPIN_WAIT __yield()
#define MPMM_PREFETCH(PTR) __prefetch((PTR), 1, 3)
#endif
#define MPMM_EXPECT(CONDITION, VALUE) (CONDITION)
#define MPMM_LIKELY_IF(CONDITION) if ((CONDITION))
#define MPMM_UNLIKELY_IF(CONDITION) if ((CONDITION))
#define MPMM_POPCNT32(MASK) __popcnt((MASK))
#define MPMM_POPCNT64(MASK) __popcnt64((MASK))
#define MPMM_CTZ32(MASK) _tzcnt_u32((MASK))
#define MPMM_CTZ64(MASK) _tzcnt_u64((MASK))
#define MPMM_CLZ32(MASK) _lzcnt_u32((MASK))
#define MPMM_CLZ64(MASK) _lzcnt_u64((MASK))
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

#define MPMM_BT32(MASK, INDEX) ((MASK) & (1U << (INDEX)))
#define MPMM_BT64(MASK, INDEX) ((MASK) & (1ULL << (INDEX)))
#define MPMM_BS32(MASK, INDEX) (MASK) |= (1U << (INDEX))
#define MPMM_BS64(MASK, INDEX) (MASK) |= (1ULL << (INDEX))
#define MPMM_BR32(MASK, INDEX) (MASK) &= ~(1U << (INDEX))
#define MPMM_BR64(MASK, INDEX) (MASK) &= ~(1ULL << (INDEX))
#define MPMM_LOG2_32(VALUE) (31 - MPMM_CLZ32(VALUE))
#define MPMM_LOG2_64(VALUE) (63 - MPMM_CLZ64(VALUE))
#define MPMM_POW2_ROUND32(VALUE) (1U << (32 - MPMM_CLZ32((VALUE) - 1U)))
#define MPMM_POW2_ROUND64(VALUE) (1ULL << (64 - MPMM_CLZ64((VALUE) - 1ULL)))

#ifdef MPMM_32BIT
#define MPMM_POPCNT(MASK) MPMM_POPCNT32((MASK))
#define MPMM_CTZ(MASK) MPMM_CTZ32((MASK))
#define MPMM_CLZ(MASK) MPMM_CLZ32((MASK))
#define MPMM_LOG2(VALUE) MPMM_LOG2_32(VALUE)
#define MPMM_POW2_ROUND(VALUE) MPMM_POW2_ROUND32(VALUE)
#define MPMM_BT(MASK, INDEX) MPMM_BT32(MASK, INDEX)
#define MPMM_BS(MASK, INDEX) MPMM_BS32(MASK, INDEX)
#define MPMM_BR(MASK, INDEX) MPMM_BR32(MASK, INDEX)
#else
#define MPMM_POPCNT(MASK) MPMM_POPCNT64((MASK))
#define MPMM_CTZ(MASK) MPMM_CTZ64((MASK))
#define MPMM_CLZ(MASK) MPMM_CLZ64((MASK))
#define MPMM_LOG2(VALUE) MPMM_LOG2_64(VALUE)
#define MPMM_POW2_ROUND(VALUE) MPMM_POW2_ROUND64(VALUE)
#define MPMM_BT(MASK, INDEX) MPMM_BT64(MASK, INDEX)
#define MPMM_BS(MASK, INDEX) MPMM_BS64(MASK, INDEX)
#define MPMM_BR(MASK, INDEX) MPMM_BR64(MASK, INDEX)
#endif

#ifdef MPMM_DEBUG
#include <assert.h>
#define MPMM_INVARIANT(EXPRESSION) assert(EXPRESSION)
#define MPMM_UNREACHABLE abort()
#else
#define MPMM_INVARIANT(EXPRESSION) MPMM_ASSUME(EXPRESSION)
#define MPMM_UNREACHABLE MPMM_ASSUME(0)
#endif

#define MPMM_ARRAY_SIZE(ARRAY) (sizeof(ARRAY) / sizeof(ARRAY[0]))
#define MPMM_BLOCK_MASK_BIT_SIZE_LOG2 (sizeof(mpmm_mask_type) == 4 ? 5 : 6)
#define MPMM_BLOCK_MASK_MOD_MASK ((1UI8 << MPMM_BLOCK_MASK_BIT_SIZE_LOG2) - 1UI8)
#define MPMM_BLOCK_ALLOCATOR_MAX_CAPACITY (MPMM_CACHE_LINE_SIZE * 8)
#define MPMM_BLOCK_ALLOCATOR_MASK_COUNT (MPMM_BLOCK_ALLOCATOR_MAX_CAPACITY / (8 * sizeof(mpmm_mask_type)))

#define MPMM_SHARED_ATTR _Alignas(MPMM_CACHE_LINE_SIZE)

#ifdef MPMM_DEBUG
#define MPMM_EMMIT_MESSAGE(MESSAGE) mpmm_debugger_message((MESSAGE), (sizeof((MESSAGE)) / sizeof((MESSAGE)[0])) - 1)
#define MPMM_EMMIT_WARNING(MESSAGE) mpmm_debugger_warning((MESSAGE), (sizeof((MESSAGE)) / sizeof((MESSAGE)[0])) - 1)
#define MPMM_EMMIT_ERROR(MESSAGE) mpmm_debugger_error((MESSAGE), (sizeof((MESSAGE)) / sizeof((MESSAGE)[0])) - 1)
#else
#define MPMM_EMMIT_MESSAGE(MESSAGE)
#define MPMM_EMMIT_WARNING(MESSAGE)
#define MPMM_EMMIT_ERROR(MESSAGE)
#endif

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
	MPMM_SIZE_MAP_0,
	MPMM_SIZE_MAP_1,
	MPMM_SIZE_MAP_2,
	MPMM_SIZE_MAP_3,
	MPMM_SIZE_MAP_4,
	MPMM_SIZE_MAP_5,
	MPMM_SIZE_MAP_6,
	MPMM_SIZE_MAP_7,
	MPMM_SIZE_MAP_8,
	MPMM_SIZE_MAP_9,
	MPMM_SIZE_MAP_10,
	MPMM_SIZE_MAP_11
};

static const uint_fast8_t MPMM_SIZE_MAP_SIZES[] =
{
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_7),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_8),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_9),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_10),
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_11)
};

static const uint_fast8_t MPMM_SIZE_CLASS_COUNT =
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_7) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_8) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_9) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_10) +
	MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_11);

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
	(uint8_t)(MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_11) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_10) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_9) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_8) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_7) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_6) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_5) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_4) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_3) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_2) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_1) + MPMM_ARRAY_SIZE(MPMM_SIZE_MAP_0))
};

#define MPMM_SIZE_MAP_SIZE MPMM_ARRAY_SIZE(MPMM_SIZE_CLASS_LOOKUP)
#define MPMM_SMALL_SIZE_CLASS_COUNT MPMM_ARRAY_SIZE(MPMM_SMALL_SIZE_CLASSES)

#ifdef MPMM_32BIT
typedef uint32_t mpmm_mask_type;
#else
typedef uint64_t mpmm_mask_type;
#endif

typedef _Atomic(mpmm_bool) mpmm_atomic_bool;
typedef _Atomic(mpmm_mask_type) mpmm_atomic_mask_type;

#ifdef MPMM_WINDOWS
static void* min_chunk;
static void* max_address;
#endif
static size_t max_concurrency;
static size_t page_size;
static size_t chunk_size;
static size_t chunk_size_mask;
static uint8_t page_size_log2;
static uint8_t chunk_size_log2;
#ifdef MPMM_DEBUG
static mpmm_debugger_options debugger;
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
	max_concurrency = info.dwNumberOfProcessors;
#else
	page_size = (size_t)getpagesize();
	chunk_size = page_size * MPMM_CACHE_LINE_SIZE * 8;
#endif
	chunk_size_mask = chunk_size - 1;
	page_size_log2 = MPMM_LOG2_64(page_size);
	chunk_size_log2 = MPMM_LOG2_64(chunk_size);
	MPMM_INVARIANT(page_size >= 4096);
	MPMM_INVARIANT(chunk_size >= (32 * 4096));
}

MPMM_INLINE_ALWAYS static size_t mpmm_chunk_index_of(void* chunk)
{
	size_t mask = (size_t)chunk;
	mask >>= chunk_size_log2;
	return mask;
}

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

MPMM_INLINE_ALWAYS static mpmm_bool mpmm_os_resize(void* ptr, size_t old_size, size_t new_size)
{
	return NULL;
}

MPMM_INLINE_ALWAYS static void mpmm_os_free(void* ptr, size_t size)
{
	MPMM_INVARIANT(ptr != NULL);
	mpmm_bool result = VirtualFree(ptr, 0, MEM_RELEASE);
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

typedef _Atomic(mpmm_thread_id) mpmm_atomic_thread_id;

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
typedef _Atomic(mpmm_flist_node*) mpmm_rlist;
typedef _Atomic(size_t) mpmm_chunk_list;

MPMM_INLINE_ALWAYS static void mpmm_chunk_list_push(mpmm_chunk_list*head, void* ptr)
{
	mpmm_flist_node* new_head = (mpmm_flist_node*)ptr;
	size_t prior, desired;
	for (;; MPMM_SPIN_WAIT)
	{
		prior = atomic_load_explicit(head, memory_order_acquire);
		new_head->next = (mpmm_flist_node*)(prior & ~chunk_size_mask);
		desired = (size_t)new_head | (((prior & chunk_size_mask) + 1) & chunk_size_mask);
		MPMM_LIKELY_IF(atomic_compare_exchange_weak_explicit(head, &prior, desired, memory_order_release, memory_order_relaxed))
			break;
	}
}

MPMM_INLINE_ALWAYS static void* mpmm_chunk_list_pop(mpmm_chunk_list* head)
{
	size_t prior, desired;
	for (;; MPMM_SPIN_WAIT)
	{
		prior = atomic_load_explicit(head, memory_order_acquire);
		mpmm_flist_node* ptr = (mpmm_flist_node*)(prior & ~chunk_size_mask);
		MPMM_UNLIKELY_IF(ptr == NULL)
			return NULL;
		desired = (size_t)ptr->next | (((prior & chunk_size_mask) + 1) & chunk_size_mask);
		MPMM_LIKELY_IF(atomic_compare_exchange_weak_explicit(head, &prior, desired, memory_order_acquire, memory_order_relaxed))
			return ptr;
	}
}

typedef struct mpmm_block_allocator
{
	alignas (MPMM_CACHE_LINE_SIZE) struct mpmm_block_allocator* next;
	mpmm_rlist* recovered;
	struct mpmm_tcache* owner;
	uint8_t* buffer;
	uint32_t free_count;
	uint8_t block_size_log2;
	mpmm_atomic_bool unlinked;
	alignas (MPMM_CACHE_LINE_SIZE) mpmm_mask_type free_map[MPMM_BLOCK_ALLOCATOR_MASK_COUNT];
	alignas (MPMM_CACHE_LINE_SIZE) mpmm_atomic_mask_type marked_map[MPMM_BLOCK_ALLOCATOR_MASK_COUNT];
} mpmm_block_allocator;

typedef struct mpmm_intrusive_block_allocator
{
	alignas (MPMM_CACHE_LINE_SIZE) struct mpmm_intrusive_block_allocator* next;
	mpmm_rlist* recovered;
	struct mpmm_tcache* owner;
	uint32_t free_count;
	uint32_t block_size;
	mpmm_atomic_bool unlinked;
	alignas (MPMM_CACHE_LINE_SIZE) mpmm_mask_type free_map[MPMM_BLOCK_ALLOCATOR_MASK_COUNT];
	alignas (MPMM_CACHE_LINE_SIZE) mpmm_atomic_mask_type marked_map[MPMM_BLOCK_ALLOCATOR_MASK_COUNT];
} mpmm_intrusive_block_allocator;

MPMM_INLINE_ALWAYS static size_t mpmm_chunk_size_of(size_t size)
{
	size *= MPMM_BLOCK_ALLOCATOR_MAX_CAPACITY;
	MPMM_UNLIKELY_IF(size > chunk_size)
		size = chunk_size;
	size = MPMM_POW2_ROUND(size);
	return size;
}

MPMM_INLINE_ALWAYS static uint_fast32_t mpmm_intrusive_block_allocator_index_of(void* buffer, size_t block_size, void* ptr)
{
	MPMM_INVARIANT(buffer != NULL);
	return ((uint_fast32_t)((uint8_t*)ptr - (uint8_t*)buffer)) / block_size;
}

MPMM_INLINE_ALWAYS static uint_fast32_t mpmm_block_allocator_index_of(void* buffer, uint_fast8_t block_size_log2, void* ptr)
{
	MPMM_INVARIANT(buffer != NULL);
	return ((uint_fast32_t)((uint8_t*)ptr - (uint8_t*)buffer)) >> block_size_log2;
}

#ifdef MPMM_DEBUG
MPMM_INLINE_ALWAYS static mpmm_bool mpmm_intrusive_block_allocator_owns(void* buffer, void* ptr, size_t block_size, mpmm_mask_type* free_map)
{
	MPMM_UNLIKELY_IF((uint8_t*)ptr < (uint8_t*)buffer || (uint8_t*)ptr >= (uint8_t*)buffer + mpmm_chunk_size_of(block_size))
		return 0;
	uint_fast32_t index = mpmm_intrusive_block_allocator_index_of(buffer, block_size, ptr);
	uint_fast32_t mask_index = index >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	uint_fast32_t bit_index = index & MPMM_BLOCK_MASK_MOD_MASK;
	return !MPMM_BT(free_map[mask_index], bit_index);
}

MPMM_INLINE_ALWAYS static mpmm_bool mpmm_block_allocator_owns(void* buffer, void* ptr, size_t block_size_log2, mpmm_mask_type* free_map)
{
	MPMM_UNLIKELY_IF((uint8_t*)ptr < (uint8_t*)buffer || (uint8_t*)ptr >= (uint8_t*)buffer + mpmm_chunk_size_of((size_t)1 << block_size_log2))
		return 0;
	uint_fast32_t index = mpmm_block_allocator_index_of(buffer, block_size_log2, ptr);
	uint_fast32_t mask_index = index >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	uint_fast32_t bit_index = index & MPMM_BLOCK_MASK_MOD_MASK;
	return !MPMM_BT(free_map[mask_index], bit_index);
}
#endif

MPMM_INLINE_ALWAYS static void mpmm_block_allocator_init(mpmm_block_allocator* self, uint_fast8_t block_size_log2, size_t chunk_size, mpmm_rlist* recovered, struct mpmm_tcache* owner, void* buffer)
{
	MPMM_INVARIANT(chunk_size_log2 > block_size_log2);
	MPMM_INVARIANT(self != NULL);
	self->next = NULL;
	self->recovered = recovered;
	self->free_count = 1U << (chunk_size_log2 - block_size_log2);
	self->block_size_log2 = block_size_log2;
	self->owner = owner;
	self->buffer = (uint8_t*)buffer;
	self->unlinked = 0;
	(void)memset(self->free_map, 0xff, sizeof(self->free_map));
	(void)memset(self->marked_map, 0, sizeof(self->marked_map));
}

MPMM_INLINE_ALWAYS static void mpmm_intrusive_block_allocator_init(mpmm_intrusive_block_allocator* self, uint_fast32_t block_size, size_t chunk_size, mpmm_rlist* recovered, struct mpmm_tcache* owner)
{
	MPMM_INVARIANT(self != NULL);
	self->next = NULL;
	self->recovered = recovered;
	uint_fast32_t reserved_count = (uint_fast32_t)MPMM_ALIGN_ROUND(sizeof(mpmm_intrusive_block_allocator), (size_t)block_size) / block_size;
	uint_fast32_t capacity = (uint_fast32_t)(chunk_size / block_size);
	self->free_count = capacity - reserved_count;
	self->block_size = block_size;
	self->owner = owner;
	self->unlinked = 0;
	(void)memset(self->free_map, 0, sizeof(self->free_map));
	(void)memset(self->marked_map, 0, sizeof(self->marked_map));
	uint_fast32_t mask_count = capacity >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	uint_fast32_t bit_count = capacity & MPMM_BLOCK_MASK_MOD_MASK;
	MPMM_LIKELY_IF(mask_count != 0)
		(void)memset(self->free_map, 0xff, mask_count * sizeof(mpmm_mask_type));
	MPMM_LIKELY_IF(bit_count != 0)
		self->free_map[mask_count] = ((mpmm_mask_type)1 << bit_count) - (mpmm_mask_type)1;
	mask_count = reserved_count >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	bit_count = reserved_count & MPMM_BLOCK_MASK_MOD_MASK;
	MPMM_LIKELY_IF(mask_count != 0)
		(void)memset(self->free_map, 0, mask_count * sizeof(mpmm_mask_type));
	MPMM_LIKELY_IF(bit_count != 0)
		self->free_map[0] &= ~(((mpmm_mask_type)1 << bit_count) - (mpmm_mask_type)1);
}

MPMM_INLINE_NEVER static uint_fast32_t mpmm_intrusive_block_allocator_reclaim(mpmm_mask_type* free_map, mpmm_atomic_mask_type* marked_map, size_t bitmask_count)
{
	uint_fast32_t freed_count = 0;
	for (uint_fast32_t i = 0; i != bitmask_count; ++i)
	{
		MPMM_LIKELY_IF(atomic_load_explicit(marked_map + i, memory_order_acquire) != 0)
		{
			mpmm_mask_type mask = atomic_exchange_explicit(marked_map + i, 0, memory_order_acquire);
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
			self->free_count += mpmm_intrusive_block_allocator_reclaim(self->free_map, self->marked_map, MPMM_BLOCK_ALLOCATOR_MASK_COUNT);
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
			self->free_count += mpmm_intrusive_block_allocator_reclaim(self->free_map, self->marked_map, MPMM_BLOCK_ALLOCATOR_MASK_COUNT);
		}
		return (uint8_t*)self + offset;
	}
	MPMM_UNREACHABLE;
}

MPMM_INLINE_NEVER static void mpmm_block_allocator_recover(atomic_bool* unlinked, mpmm_rlist* recovered, void* self)
{
	mpmm_flist_node* desired;
	mpmm_bool expected = 0;
	MPMM_UNLIKELY_IF(atomic_compare_exchange_strong_explicit(unlinked, &expected, 0, memory_order_acquire, memory_order_relaxed))
		return;
	desired = (mpmm_flist_node*)self;
	for (;; MPMM_SPIN_WAIT)
	{
		desired->next = atomic_load_explicit(recovered, memory_order_acquire);
		MPMM_LIKELY_IF(atomic_compare_exchange_weak_explicit(recovered, &desired->next, desired, memory_order_release, memory_order_relaxed))
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
	MPMM_UNLIKELY_IF(atomic_load_explicit(&self->unlinked, memory_order_acquire))
		mpmm_block_allocator_recover(&self->unlinked, self->recovered, self);
}

MPMM_INLINE_ALWAYS static void mpmm_intrusive_block_allocator_free_shared(mpmm_intrusive_block_allocator* self, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	index = mpmm_intrusive_block_allocator_index_of(self, self->block_size, ptr);
	mask_index = index >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	bit_index = index & MPMM_BLOCK_MASK_MOD_MASK;
	atomic_fetch_or_explicit(self->marked_map + mask_index, (mpmm_mask_type)1 << bit_index, memory_order_release);
	MPMM_UNLIKELY_IF(atomic_load_explicit(&self->unlinked, memory_order_acquire))
		mpmm_block_allocator_recover(&self->unlinked, self->recovered, self);
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
	MPMM_UNLIKELY_IF(atomic_load_explicit(&self->unlinked, memory_order_acquire))
		mpmm_block_allocator_recover(&self->unlinked, self->recovered, self);
}

MPMM_INLINE_ALWAYS static void mpmm_block_allocator_free_shared(mpmm_block_allocator* self, void* ptr)
{
	uint_fast32_t index, mask_index, bit_index;
	index = mpmm_block_allocator_index_of(self, self->block_size_log2, ptr);
	mask_index = index >> MPMM_BLOCK_MASK_BIT_SIZE_LOG2;
	bit_index = index & MPMM_BLOCK_MASK_MOD_MASK;
	atomic_fetch_or_explicit(self->marked_map + mask_index, (mpmm_mask_type)1 << bit_index, memory_order_release);
	MPMM_UNLIKELY_IF(atomic_load_explicit(&self->unlinked, memory_order_acquire))
		mpmm_block_allocator_recover(&self->unlinked, self->recovered, self);
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

typedef struct mpmm_shared_counter { alignas (MPMM_CACHE_LINE_SIZE) atomic_size_t value; } mpmm_shared_counter;

static mpmm_shared_counter used_memory;
static mpmm_shared_counter total_memory;

// ================================================================
//	PERSISTENT
// ================================================================

typedef struct persistent_node
{
	alignas (MPMM_CACHE_LINE_SIZE)
	struct persistent_node* next;
	atomic_size_t bump;
} persistent_node;

typedef _Atomic(persistent_node*) persistent_allocator;

MPMM_INLINE_ALWAYS static void* mpmm_persistent_node_malloc(persistent_node* self, size_t size)
{
	size_t prior = atomic_fetch_add_explicit(&self->bump, size, memory_order_acquire);
	MPMM_LIKELY_IF(prior + size <= chunk_size)
		return (uint8_t*)self + prior;
	(void)atomic_fetch_sub_explicit(&self->bump, size, memory_order_release);
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
	current = atomic_load_explicit(allocator, memory_order_acquire);
	do
	{
		prior = current;
		for (n = prior; n != NULL; n = n->next)
		{
			r = mpmm_persistent_node_malloc(n, size);
			MPMM_LIKELY_IF(r != NULL)
				return r;
		}
		current = atomic_load_explicit(allocator, memory_order_acquire);
	} while (prior != current);
	n = (persistent_node*)mpmm_lcache_malloc(chunk_size, MPMM_ENABLE_FALLBACK);
	MPMM_INVARIANT(n != NULL);
	offset = MPMM_ALIGN_ROUND(sizeof(persistent_node), MPMM_CACHE_LINE_SIZE);
	r = (uint8_t*)n + offset;
	offset += size;
	n->bump = offset;
	for (;; MPMM_SPIN_WAIT)
	{
		prior = atomic_load_explicit(allocator, memory_order_acquire);
		n->next = prior;
		MPMM_LIKELY_IF(atomic_compare_exchange_weak_explicit(allocator, &prior, n, memory_order_release, memory_order_relaxed))
			return r;
	}
}

MPMM_ATTR void MPMM_CALL mpmm_persistent_reset_impl(persistent_allocator* allocator)
{
	persistent_node* next;
	persistent_node* n;
	for (n = atomic_exchange_explicit(allocator, NULL, memory_order_acquire); n != NULL; n = next)
	{
		next = n->next;
		backend_free(n, chunk_size);
	}
}

// ================================================================
//	LARGE CACHE
// ================================================================

#ifdef MPMM_32BIT
static size_t lcache_bin_count;
static mpmm_chunk_list* lcache_bins;
#else
#endif

MPMM_INLINE_ALWAYS static void mpmm_lcache_init()
{
#ifdef MPMM_32BIT
	lcache_bin_count = 1 << (32 - chunk_size_log2);
	lcache_bins = (mpmm_chunk_list*)mpmm_persistent_malloc_impl(&internal_persistent_allocator, lcache_bin_count * sizeof(mpmm_chunk_list));
	MPMM_INVARIANT(lcache_bins != NULL);
#else
#endif
}

MPMM_INLINE_ALWAYS static mpmm_chunk_list* mpmm_lcache_find_bin(size_t size)
{
	size >>= chunk_size_log2;
	MPMM_INVARIANT(size != 0);
	--size;
#ifdef MPMM_32BIT
	return lcache_bins + size;
#else
#endif
}

MPMM_INLINE_ALWAYS static mpmm_chunk_list* mpmm_lcache_find_or_insert_bin(size_t size)
{
#ifdef MPMM_32BIT
	return mpmm_lcache_find_bin(size);
#else
#endif
}

// ================================================================
//	THREAD CACHE
// ================================================================

#ifdef MPMM_32BIT
static mpmm_block_allocator* tcache_lookup;
#else
#endif

MPMM_INLINE_ALWAYS static void mpmm_tcache_common_init()
{
	size_t k = 1 << (32 - chunk_size_log2);
	tcache_lookup = (mpmm_block_allocator*)mpmm_persistent_malloc_impl(&internal_persistent_allocator, sizeof(mpmm_block_allocator) * k);
}

typedef struct mpmm_tcache
{
	mpmm_intrusive_block_allocator** bins;
	mpmm_rlist* recovered;
	mpmm_block_allocator** bins_large;
	mpmm_rlist* recovered_large;
} mpmm_tcache;

static _Thread_local mpmm_tcache this_thread_cache;

MPMM_INLINE_ALWAYS static mpmm_block_allocator* mpmm_tcache_find_allocator(void* buffer)
{
	size_t id = mpmm_chunk_index_of(buffer);
#ifdef MPMM_32BIT
	MPMM_INVARIANT(tcache_lookup != NULL);
	return tcache_lookup + id;
#else
#endif
}

MPMM_INLINE_ALWAYS static mpmm_block_allocator* mpmm_tcache_find_or_insert_allocator(void* buffer)
{
#ifdef MPMM_32BIT
	return mpmm_tcache_find_allocator(buffer);
#else
#endif
}

MPMM_INLINE_ALWAYS static mpmm_block_allocator* mpmm_tcache_block_allocator_of(void* ptr)
{
	size_t mask = (size_t)ptr;
	mask &= ~chunk_size_mask;
	return mpmm_tcache_find_allocator((void*)mask);
}

MPMM_INLINE_ALWAYS static void mpmm_tcache_init(mpmm_tcache* tcache)
{
	const size_t n = sizeof(void*) * MPMM_SIZE_CLASS_COUNT;
	const size_t m = sizeof(void*) * (chunk_size_log2 - 12);
	uint8_t* buffer = (uint8_t*)mpmm_persistent_malloc_impl(&internal_persistent_allocator, n * 2 + m * 2);
	tcache->bins = (mpmm_intrusive_block_allocator**)buffer;
	buffer += n;
	tcache->recovered = (mpmm_rlist*)buffer;
	buffer += n;
	tcache->bins_large = (mpmm_block_allocator**)buffer;
	buffer += m;
	tcache->recovered_large = (mpmm_rlist*)buffer;
}

MPMM_INLINE_ALWAYS static mpmm_tcache* mpmm_get_tcache()
{
	MPMM_UNLIKELY_IF(this_thread_cache.bins == NULL)
		mpmm_tcache_init(&this_thread_cache);
	return &this_thread_cache;
}

MPMM_INLINE_ALWAYS static uint_fast32_t mpmm_tcache_size_class(size_t size)
{
	uint_fast8_t log2 = MPMM_LOG2(size);
	uint_fast8_t limit = MPMM_SIZE_MAP_SIZE;
	MPMM_UNLIKELY_IF(log2 >= limit)
		return MPMM_SIZE_CLASS_COUNT + MPMM_LOG2_32((uint32_t)size) - 12;
	const uint_fast32_t* map = MPMM_SIZE_CLASS_LOOKUP[log2];
	uint_fast32_t map_size = MPMM_SIZE_MAP_SIZES[log2];
	uint_fast32_t offset = MPMM_SIZE_MAP_OFFSETS[log2];
	uint_fast8_t i = 0;
	for (; i != map_size; ++i)
		MPMM_LIKELY_IF(map[i] >= size)
			return offset + i;
	MPMM_UNREACHABLE;
}

MPMM_INLINE_ALWAYS static void* mpmm_tcache_malloc_small_slow(mpmm_tcache* tcache, size_t size, uint_fast32_t sc)
{
	void* r;
	size_t k;
	mpmm_intrusive_block_allocator* allocator;
	mpmm_intrusive_block_allocator** bin;

	k = mpmm_chunk_size_of(size);
	allocator = (mpmm_intrusive_block_allocator*)mpmm_malloc(k);
	MPMM_UNLIKELY_IF(allocator == NULL)
		return NULL;
	mpmm_intrusive_block_allocator_init(allocator, size, k, tcache->recovered + sc, mpmm_get_tcache());
	r = mpmm_intrusive_block_allocator_malloc(allocator);
	bin = tcache->bins + sc;
	allocator->next = *bin;
	*bin = allocator;
	return r;
}

MPMM_INLINE_ALWAYS static void* mpmm_tcache_malloc_large_slow(mpmm_tcache* tcache, size_t size, uint_fast32_t sc)
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
	allocator = mpmm_tcache_find_or_insert_allocator(buffer);
	MPMM_INVARIANT(allocator != NULL);
	mpmm_block_allocator_init(allocator, MPMM_LOG2(size), k, tcache->recovered_large + sc, mpmm_get_tcache(), buffer);
	r = mpmm_block_allocator_malloc(allocator);
	bin = tcache->bins_large + sc;
	allocator->next = *bin;
	*bin = allocator;
	return r;
}

MPMM_INLINE_ALWAYS static void* mpmm_tcache_malloc_small_fast(mpmm_tcache* tcache, size_t size, uint_fast32_t sc, uint_fast64_t flags)
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
		allocator = (mpmm_intrusive_block_allocator*)atomic_exchange_explicit(recover_list, NULL, memory_order_acquire);
		MPMM_UNLIKELY_IF(allocator == NULL)
			return (flags & MPMM_ENABLE_FALLBACK) ? mpmm_tcache_malloc_small_slow(tcache, size, sc) : NULL;
		*bin = (mpmm_intrusive_block_allocator*)allocator;
	}
	r = mpmm_intrusive_block_allocator_malloc(allocator);
	MPMM_INVARIANT(r != NULL);
	MPMM_UNLIKELY_IF(allocator->free_count == 0)
	{
		atomic_store_explicit(&allocator->unlinked, 1, memory_order_release);
		*bin = (*bin)->next;
		allocator->next = NULL;
	}
	return r;
}

MPMM_INLINE_ALWAYS static void* mpmm_tcache_malloc_large_fast(mpmm_tcache* tcache, size_t size, uint_fast32_t sc, uint_fast64_t flags)
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
		allocator = (mpmm_block_allocator*)atomic_exchange_explicit(recover_list, NULL, memory_order_acquire);
		MPMM_UNLIKELY_IF(allocator == NULL)
			return (flags & MPMM_ENABLE_FALLBACK) ? mpmm_tcache_malloc_large_slow(tcache, size, sc) : NULL;
		*bin = (mpmm_block_allocator*)allocator;
	}
	r = mpmm_block_allocator_malloc(allocator);
	MPMM_INVARIANT(r != NULL);
	MPMM_UNLIKELY_IF(allocator->free_count == 0)
	{
		atomic_store_explicit(&allocator->unlinked, 1, memory_order_release);
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
#endif

// ================================================================
//	MAIN API
// ================================================================

MPMM_EXTERN_C_BEGIN
MPMM_ATTR void MPMM_CALL mpmm_init_info_default(mpmm_init_options* out_options)
{
	out_options->max_concurrency = 0;
	out_options->backend = NULL;
}

MPMM_ATTR void MPMM_CALL mpmm_trim_options_default(mpmm_trim_options* out_options)
{
	out_options->trim_limit = SIZE_MAX;
}

MPMM_ATTR void MPMM_CALL mpmm_debugger_options_default(mpmm_debugger_options* out_options)
{
	out_options->context = NULL;
	out_options->message = mpmm_default_debugger_message_callback;
	out_options->warning = mpmm_default_debugger_warning_callback;
	out_options->error = mpmm_default_debugger_error_callback;
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
		max_concurrency = options->max_concurrency;
		MPMM_INVARIANT(max_concurrency < chunk_size);
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
	mpmm_tcache_common_init();
}

MPMM_ATTR mpmm_bool MPMM_CALL mpmm_is_initialized()
{
	return lcache_bins != NULL;
}

MPMM_ATTR void MPMM_CALL mpmm_reset()
{
	mpmm_persistent_reset_impl(&public_persistent_allocator);
}

MPMM_ATTR void MPMM_CALL mpmm_stats(mpmm_mem_stats* out_stats)
{
}

MPMM_ATTR void MPMM_CALL mpmm_params(mpmm_global_params* out_params)
{
	out_params->page_size = page_size;
	out_params->chunk_size = chunk_size;
	out_params->max_concurrency = max_concurrency;
}

MPMM_ATTR void* MPMM_CALL mpmm_malloc(size_t size)
{
	void* r;
	size = mpmm_round_size(size);
	MPMM_LIKELY_IF(size <= mpmm_tcache_max_size())
		r = mpmm_tcache_malloc(size, MPMM_ENABLE_FALLBACK);
	else
		r = mpmm_lcache_malloc(size, MPMM_ENABLE_FALLBACK);
	MPMM_DEBUG_JUNK_FILL(r, size);
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

MPMM_ATTR size_t MPMM_CALL mpmm_purge(uint64_t flags, void* param)
{
	return 0;
}

MPMM_ATTR size_t MPMM_CALL mpmm_trim(const mpmm_trim_options* options)
{
	return 0;
}

MPMM_ATTR void* MPMM_CALL mpmm_tcache_malloc(size_t size, uint64_t flags)
{
	void* r;
	uint_fast32_t sc;
	mpmm_tcache* tcache;
	
	tcache = mpmm_get_tcache();
	sc = mpmm_tcache_size_class(size);
	if (size <= page_size)
		r = mpmm_tcache_malloc_small_fast(tcache, size, sc, flags);
	else
		r = mpmm_tcache_malloc_large_fast(tcache, size, sc, flags);
	return r;
}

MPMM_ATTR void MPMM_CALL mpmm_tcache_free(void* ptr, size_t size)
{
	size_t k = mpmm_chunk_size_of(size);
	if (size <= page_size)
	{
		mpmm_intrusive_block_allocator* allocator = (mpmm_intrusive_block_allocator*)mpmm_intrusive_block_allocator_allocator_of(ptr, k);
		if (allocator->owner == mpmm_get_tcache())
			mpmm_intrusive_block_allocator_free(allocator, ptr);
		else
			mpmm_intrusive_block_allocator_free_shared(allocator, ptr);
	}
	else
	{
		mpmm_block_allocator* allocator = mpmm_tcache_block_allocator_of(ptr);
		if (allocator->owner == mpmm_get_tcache())
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

MPMM_ATTR size_t MPMM_CALL mpmm_tcache_flush(uint64_t flags, void* param)
{
	return 0;
}

MPMM_ATTR size_t MPMM_CALL mpmm_tcache_min_size() { return 1; }
MPMM_ATTR size_t MPMM_CALL mpmm_tcache_max_size() { return chunk_size / 2; }

MPMM_ATTR void* MPMM_CALL mpmm_lcache_malloc(size_t size, uint64_t flags)
{
	void* r = NULL;
	mpmm_chunk_list* bin = mpmm_lcache_find_bin(size);
	if (bin != NULL)
		r = mpmm_chunk_list_pop(bin);
	MPMM_UNLIKELY_IF(r == NULL && (flags & MPMM_ENABLE_FALLBACK))
		r = backend_malloc(size);
	return r;
}

MPMM_ATTR void MPMM_CALL mpmm_lcache_free(void* ptr, size_t size)
{
	mpmm_chunk_list* bin = mpmm_lcache_find_or_insert_bin(size);
	MPMM_INVARIANT(bin != NULL);
	mpmm_backend_purge((uint8_t*)ptr + page_size, size - page_size);
	mpmm_chunk_list_push(bin, ptr);
}

MPMM_ATTR size_t MPMM_CALL mpmm_lcache_round_size(size_t size)
{
	return MPMM_ALIGN_ROUND(size, chunk_size);
}

MPMM_ATTR size_t MPMM_CALL mpmm_lcache_flush(uint64_t flags, void* param)
{
	return 0;
}

MPMM_ATTR size_t MPMM_CALL mpmm_lcache_min_size() { return chunk_size; }
MPMM_ATTR size_t MPMM_CALL mpmm_lcache_max_size() { return SIZE_MAX; }

MPMM_ATTR void* MPMM_CALL mpmm_persistent_malloc(size_t size)
{
	return mpmm_persistent_malloc_impl(&internal_persistent_allocator, size);
}

MPMM_ATTR void MPMM_CALL mpmm_persistent_reset()
{
	mpmm_persistent_reset_impl(&public_persistent_allocator);
}

MPMM_ATTR void* MPMM_CALL mpmm_backend_malloc(size_t size)
{
	MPMM_INVARIANT(backend_malloc != NULL);
	void* r = backend_malloc(size);
	MPMM_UNLIKELY_IF(r == NULL)
		size = 0;
	return r;
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