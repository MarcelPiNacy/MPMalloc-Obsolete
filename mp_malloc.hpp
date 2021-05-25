#ifndef MP_CXX_API
#include "mp_malloc.h"
#define MP_CXX_API

namespace mp
{
	using init_options = mp_init_options;
	using memory_stats = mp_heap_stats;
	using debug_options = mp_debug_options;

	MP_ATTR void			MP_CALL init(const mp_init_options* options) noexcept { return mp_init(options); }
	MP_ATTR void			MP_CALL init() noexcept { return mp_init_default(); }
	MP_ATTR void			MP_CALL cleanup() noexcept { mp_cleanup(); }
	MP_ATTR void* MP_CALL malloc(size_t size) noexcept { return mp_malloc(size); }
	MP_ATTR bool			MP_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept { return mp_resize(ptr, old_size, new_size); }
	MP_ATTR void* MP_CALL realloc(void* ptr, size_t old_size, size_t new_size) noexcept { return mp_realloc(ptr, old_size, new_size); }
	MP_ATTR void			MP_CALL free(void* ptr, size_t size) noexcept { mp_free(ptr, size); }
	MP_ATTR size_t			MP_CALL round_size(size_t size) noexcept { return mp_round_size(size); }

	namespace thread_cache
	{
		MP_ATTR void* MP_CALL malloc(size_t size, mp_flags flags) noexcept { return mp_tcache_malloc(size, flags); }
		MP_ATTR bool		MP_CALL resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags) noexcept { return mp_tcache_resize(ptr, old_size, new_size, flags); }
		MP_ATTR void		MP_CALL free(void* ptr, size_t size) noexcept { mp_tcache_free(ptr, size); }
		MP_ATTR size_t		MP_CALL round_size(size_t size) noexcept { return mp_tcache_round_size(size); }
		MP_ATTR size_t		MP_CALL min_size() noexcept { return mp_tcache_min_size(); }
		MP_ATTR size_t		MP_CALL max_size() noexcept { return mp_tcache_max_size(); }
	}

	namespace large_cache
	{
		MP_ATTR void* MP_CALL malloc(size_t size, mp_flags flags) noexcept { return mp_lcache_malloc(size, flags); }
		MP_ATTR bool		MP_CALL resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags) noexcept { return mp_lcache_resize(ptr, old_size, new_size, flags); }
		MP_ATTR void		MP_CALL free(void* ptr, size_t size) noexcept { mp_lcache_free(ptr, size); }
		MP_ATTR size_t		MP_CALL round_size(size_t size) noexcept { return mp_lcache_round_size(size); }
		MP_ATTR size_t		MP_CALL min_size() noexcept { return mp_lcache_min_size(); }
		MP_ATTR size_t		MP_CALL max_size() noexcept { return mp_lcache_max_size(); }
	}

	namespace persistent
	{
		MP_ATTR void* MP_CALL malloc(size_t size) noexcept { return mp_persistent_malloc(size); }
		MP_ATTR void		MP_CALL cleanup() noexcept { mp_persistent_cleanup(); }
	}

	namespace backend
	{
		MP_ATTR size_t		MP_CALL required_alignment() noexcept { return mp_backend_required_alignment(); }
		MP_ATTR void* MP_CALL malloc(size_t size) noexcept { return mp_backend_malloc(size); }
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