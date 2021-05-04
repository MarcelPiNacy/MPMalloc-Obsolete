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

namespace mpmm
{
	struct init_options : mpmm_init_options
	{
		inline init_options() noexcept { mpmm_init_info_default((mpmm_init_options*)this); }
		~init_options() = default;
	};

	using memory_stats = mpmm_mem_stats;

	struct trim_options : mpmm_trim_options
	{
		inline trim_options() noexcept { mpmm_trim_options_default((mpmm_trim_options*)this); }
		~trim_options() = default;
	};

	struct debugger_options : mpmm_debugger_options
	{
		inline debugger_options() noexcept { mpmm_debugger_options_default((mpmm_debugger_options*)this); }
		~debugger_options() = default;
	};

	MPMM_ATTR size_t MPMM_CALL backend_required_alignment() noexcept
	{
		return mpmm_backend_required_alignment();
	}

	MPMM_ATTR void MPMM_CALL init(const mpmm_init_options* options) noexcept
	{
		return mpmm_init(options);
	}

	MPMM_ATTR void MPMM_CALL reset() noexcept
	{
		mpmm_reset();
	}

	MPMM_ATTR memory_stats MPMM_CALL stats() noexcept
	{
		mpmm_mem_stats r;
		mpmm_stats(&r);
		return r;
	}

	MPMM_ATTR void* MPMM_CALL malloc(size_t size) noexcept
	{
		return mpmm_malloc(size);
	}

	MPMM_ATTR bool MPMM_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept
	{
		return mpmm_resize(ptr, old_size, new_size);
	}

	MPMM_ATTR void* MPMM_CALL realloc(void* ptr, size_t old_size, size_t new_size) noexcept
	{
		return mpmm_realloc(ptr, old_size, new_size);
	}

	MPMM_ATTR void MPMM_CALL free(void* ptr, size_t size) noexcept
	{
		mpmm_free(ptr, size);
	}

	MPMM_ATTR size_t MPMM_CALL round_size(size_t size) noexcept
	{
		return mpmm_round_size(size);
	}

	MPMM_ATTR size_t MPMM_CALL purge() noexcept
	{
		return mpmm_purge();
	}

	MPMM_ATTR size_t MPMM_CALL trim(const trim_options* options) noexcept
	{
		return mpmm_trim((const mpmm_trim_options*)options);
	}

	namespace thread_cache
	{
		MPMM_ATTR void* MPMM_CALL malloc(size_t size, uint64_t flags) noexcept
		{
			return mpmm_tcache_malloc(size, flags);
		}

		MPMM_ATTR void MPMM_CALL free(void* ptr, size_t size) noexcept
		{
			mpmm_tcache_free(ptr, size);
		}

		MPMM_ATTR size_t MPMM_CALL round_size(size_t size) noexcept
		{
			return mpmm_tcache_round_size(size);
		}

		MPMM_ATTR size_t MPMM_CALL flush() noexcept
		{
			return mpmm_tcache_flush();
		}

		MPMM_ATTR size_t MPMM_CALL min_malloc_size() noexcept
		{
			return mpmm_tcache_min_malloc_size();
		}

		MPMM_ATTR size_t MPMM_CALL max_malloc_size() noexcept
		{
			return mpmm_tcache_max_malloc_size();
		}
	}

	namespace shared_cache
	{
		MPMM_ATTR void* MPMM_CALL malloc(size_t size, uint64_t flags) noexcept
		{
			return mpmm_scache_malloc(size, flags);
		}

		MPMM_ATTR void MPMM_CALL free(void* ptr, size_t size) noexcept
		{
			mpmm_scache_free(ptr, size);
		}

		MPMM_ATTR size_t MPMM_CALL round_size(size_t size) noexcept
		{
			return mpmm_scache_round_size(size);
		}

		MPMM_ATTR size_t MPMM_CALL flush() noexcept
		{
			return mpmm_scache_flush();
		}

		MPMM_ATTR size_t MPMM_CALL min_malloc_size() noexcept
		{
			return mpmm_scache_min_malloc_size();
		}

		MPMM_ATTR size_t MPMM_CALL max_malloc_size() noexcept
		{
			return mpmm_scache_max_malloc_size();
		}
	}

	namespace large_cache
	{
		MPMM_ATTR void* MPMM_CALL malloc(size_t size, uint64_t flags) noexcept
		{
			return mpmm_lcache_malloc(size, flags);
		}

		MPMM_ATTR void MPMM_CALL free(void* ptr, size_t size) noexcept
		{
			mpmm_lcache_free(ptr, size);
		}

		MPMM_ATTR size_t MPMM_CALL round_size(size_t size) noexcept
		{
			return mpmm_lcache_round_size(size);
		}

		MPMM_ATTR size_t MPMM_CALL flush() noexcept
		{
			return mpmm_lcache_flush();
		}

		MPMM_ATTR size_t MPMM_CALL min_malloc_size() noexcept
		{
			return mpmm_lcache_min_malloc_size();
		}

		MPMM_ATTR size_t MPMM_CALL max_malloc_size() noexcept
		{
			return mpmm_lcache_max_malloc_size();
		}
	}

	namespace persistent
	{
		MPMM_ATTR void* MPMM_CALL malloc(size_t size) noexcept
		{
			return mpmm_persistent_malloc(size);
		}

		MPMM_ATTR void MPMM_CALL reset() noexcept
		{
			mpmm_persistent_reset();
		}
	}

	namespace backend
	{
		MPMM_ATTR void* MPMM_CALL malloc(size_t size) noexcept
		{
			return mpmm_backend_malloc(size);
		}

		MPMM_ATTR bool	MPMM_CALL resize(void* ptr, size_t old_size, size_t new_size) noexcept
		{
			return mpmm_backend_resize(ptr, old_size, new_size);
		}

		MPMM_ATTR void MPMM_CALL free(void* ptr, size_t size) noexcept
		{
			return mpmm_backend_free(ptr, size);
		}
	}

	namespace debugger
	{
		MPMM_ATTR void MPMM_CALL init(const debugger_options* options) noexcept
		{
			return mpmm_debugger_init((const mpmm_debugger_options*)options);
		}

		MPMM_ATTR bool	MPMM_CALL enabled() noexcept
		{
			return mpmm_debugger_enabled();
		}

		MPMM_ATTR void MPMM_CALL message(const char* message, size_t size) noexcept
		{
			return mpmm_debugger_message(message, size);
		}

		MPMM_ATTR void MPMM_CALL warning(const char* message, size_t size) noexcept
		{
			return mpmm_debugger_warning(message, size);
		}

		MPMM_ATTR void MPMM_CALL error(const char* message, size_t size) noexcept
		{
			return mpmm_debugger_error(message, size);
		}
	}
}