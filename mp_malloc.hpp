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

#ifndef MP_CXX_API
#include "mp_malloc.h"
#define MP_CXX_API

namespace mp
{
	using init_options = mp_init_options;
	using usage_stats = mp_usage_stats;
	using debug_options = mp_debug_options;

	MP_ATTR inline bool			MP_CALL init(const init_options& options) noexcept { return mp_init(&options); }
	MP_ATTR inline bool			MP_CALL init() noexcept { return mp_init_default(); }
	MP_ATTR inline void			MP_CALL cleanup() noexcept { mp_cleanup(); }
	MP_ATTR inline void			MP_CALL thread_init() noexcept { return mp_thread_init(); }
	MP_ATTR inline void			MP_CALL thread_cleanup() noexcept { mp_thread_cleanup(); }
	MP_ATTR inline void*		MP_CALL malloc(size_t size) noexcept { return mp_malloc(size); }
	MP_ATTR inline bool			MP_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept { return mp_resize_sized(ptr, old_size, new_size); }
	MP_ATTR inline void*		MP_CALL realloc(void* ptr, size_t old_size, size_t new_size) noexcept { return mp_realloc_sized(ptr, old_size, new_size); }
	MP_ATTR inline void			MP_CALL free(void* ptr, size_t size) noexcept { mp_free_sized(ptr, size); }
	MP_ATTR inline size_t		MP_CALL round_size(size_t size) noexcept { return mp_round_size(size); }

	namespace tcache
	{
		MP_ATTR inline void*	MP_CALL malloc(size_t size, mp_flags flags) noexcept { return mp_tcache_malloc(size, flags); }
		MP_ATTR inline bool		MP_CALL resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags) noexcept { return mp_tcache_resize(ptr, old_size, new_size, flags); }
		MP_ATTR inline void		MP_CALL free(void* ptr, size_t size) noexcept { mp_tcache_free(ptr, size); }
		MP_ATTR inline size_t	MP_CALL round_size(size_t size) noexcept { return mp_tcache_round_size(size); }
		MP_ATTR inline size_t	MP_CALL min_size() noexcept { return mp_tcache_min_size(); }
		MP_ATTR inline size_t	MP_CALL max_size() noexcept { return mp_tcache_max_size(); }
	}

	namespace lcache
	{
		MP_ATTR inline void*	MP_CALL malloc(size_t size, mp_flags flags) noexcept { return mp_lcache_malloc(size, flags); }
		MP_ATTR inline bool		MP_CALL resize(void* ptr, size_t old_size, size_t new_size, mp_flags flags) noexcept { return mp_lcache_resize(ptr, old_size, new_size, flags); }
		MP_ATTR inline void		MP_CALL free(void* ptr, size_t size) noexcept { mp_lcache_free(ptr, size); }
		MP_ATTR inline size_t	MP_CALL round_size(size_t size) noexcept { return mp_lcache_round_size(size); }
		MP_ATTR inline size_t	MP_CALL min_size() noexcept { return mp_lcache_min_size(); }
		MP_ATTR inline size_t	MP_CALL max_size() noexcept { return mp_lcache_max_size(); }
	}

	namespace persistent
	{
		MP_ATTR inline void*	MP_CALL malloc(size_t size) noexcept { return mp_persistent_malloc(size); }
		MP_ATTR inline void		MP_CALL cleanup() noexcept { mp_persistent_cleanup(); }
	}

	namespace backend
	{
		MP_ATTR inline size_t	MP_CALL required_alignment() noexcept { return mp_backend_required_alignment(); }
		MP_ATTR inline void*	MP_CALL malloc(size_t size) noexcept { return mp_backend_malloc(size); }
		MP_ATTR inline bool		MP_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept { return mp_backend_resize(ptr, old_size, new_size); }
		MP_ATTR inline void		MP_CALL free(void* ptr, size_t size) noexcept { return mp_backend_free(ptr, size); }
	}

	namespace debug
	{
		MP_ATTR inline void		MP_CALL init() noexcept { return mp_debug_init_default(); }
		MP_ATTR inline void		MP_CALL init(const debug_options& options) noexcept { return mp_debug_init(&options); }
		MP_ATTR inline bool		MP_CALL enabled() noexcept { return mp_debug_enabled(); }
		MP_ATTR inline void		MP_CALL message(const char* message, size_t size) noexcept { return mp_debug_message(message, size); }
		MP_ATTR inline void		MP_CALL warning(const char* message, size_t size) noexcept { return mp_debug_warning(message, size); }
		MP_ATTR inline void		MP_CALL error(const char* message, size_t size) noexcept { return mp_debug_error(message, size); }
	}
}
#endif