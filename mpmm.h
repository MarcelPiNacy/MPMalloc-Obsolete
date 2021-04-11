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

#include <cstdint>



namespace mpmm
{
	void init() noexcept;
	bool is_initialized() noexcept;
	void finalize() noexcept;
	void init_thread() noexcept;
	bool is_initialized_thread() noexcept;
	void finalize_thread() noexcept;

	[[nodiscard]]
	void* allocate(size_t size) noexcept;
	bool try_expand(void* ptr, size_t old_size, size_t new_size) noexcept;
	[[nodiscard]]
	void* reallocate(void* ptr, size_t old_size, size_t new_size) noexcept;
	void deallocate(void* ptr, size_t size) noexcept;
	size_t block_size_of(size_t size) noexcept;
	size_t trim() noexcept;
	size_t purge() noexcept;

	namespace chunk_cache
	{
		[[nodiscard]]
		void* try_allocate(size_t size) noexcept;
		[[nodiscard]]
		void* allocate(size_t size) noexcept;
		void deallocate(void* ptr, size_t size) noexcept;
		size_t block_size_of(size_t size) noexcept;
		size_t trim() noexcept;
		size_t purge() noexcept;
	}

	namespace shared_cache
	{
		[[nodiscard]]
		void* try_allocate(size_t size) noexcept;
		[[nodiscard]]
		void* allocate(size_t size) noexcept;
		void deallocate(void* ptr, size_t size) noexcept;
		size_t block_size_of(size_t size) noexcept;
		size_t trim() noexcept;
		size_t purge() noexcept;
	}

	namespace thread_cache
	{
		[[nodiscard]]
		void* try_allocate(size_t size) noexcept;
		[[nodiscard]]
		void* allocate(size_t size) noexcept;
		void deallocate(void* ptr, size_t size) noexcept;
		size_t block_size_of(size_t size) noexcept;
		size_t trim() noexcept;
		size_t purge() noexcept;
	}
}



#ifdef MPMM_IMPLEMENTATION
#include <new>
#include <atomic>
#include <cstdint>
#include <shared_mutex>

#if UINT32_MAX == UINTPTR_MAX
#define MPMM_32BIT
#else
#define MPMM_64BIT
#endif

#if !defined(MPMM_DEBUG) && (defined(_DEBUG) || !defined(NDEBUG))
#define MPMM_DEBUG
#endif

#if !defined(MPMM_JUNK_VALUE) && !defined(MPMM_NO_JUNK)
#define MPMM_JUNK_VALUE 0xcd
#endif

#ifndef MPMM_SHARED_ATTR
#define MPMM_SHARED_ATTR alignas(std::hardware_destructive_interference_size)
#endif

#define MPMM_ALIGN_FLOOR(VALUE, ALIGNMENT) ((VALUE) & ~((ALIGNMENT) - 1))
#define MPMM_ALIGN_ROUND(VALUE, ALIGNMENT) ((VALUE + ((ALIGNMENT) - 1)) & ~((ALIGNMENT) - 1))
#define MPMM_ALIGN_FLOOR_LOG2(VALUE, ALIGNMENT_LOG2) MPMM_ALIGN_FLOOR(VALUE, ((size_t)1 << (size_t)ALIGNMENT_LOG2))
#define MPMM_ALIGN_ROUND_LOG2(VALUE, ALIGNMENT_LOG2) MPMM_ALIGN_ROUND(VALUE, ((size_t)1 << (size_t)ALIGNMENT_LOG2))

#ifdef _WIN32
#define MPMM_WINDOWS
#include <Windows.h>
#define MPMM_SPIN_WAIT YieldProcessor()
#else
#error "MPMM: UNSUPPORTED OS"
#endif

#ifdef _MSVC_LANG
#define MPMM_ROL64(MASK, COUNT)  ((uint8_t)_rotl64((MASK), (COUNT)))
#define MPMM_POPCOUNT8(MASK)  ((uint8_t)__popcnt16((MASK)))
#define MPMM_POPCOUNT16(MASK) ((uint8_t)__popcnt16((MASK)))
#define MPMM_POPCOUNT32(MASK) ((uint8_t)__popcnt((MASK)))
#ifdef MPMM_32BIT
#define MPMM_POPCOUNT64(MASK) (MPMM_POPCOUNT32((uint32_t)((MASK))) + MPMM_POPCOUNT32((uint32_t)((MASK) >> 32)))
#else
#define MPMM_POPCOUNT64(MASK) ((uint8_t)__popcnt64((MASK)))
#endif
#define MPMM_INLINE_ALWAYS __forceinline
#define MPMM_INLINE_NEVER __declspec(noinline)
#define MPMM_ASSUME(EXPRESSION) __assume(EXPRESSION)
#ifdef MPMM_DEBUG
#include <cassert>
#define MPMM_INVARIANT(EXPRESSION) assert(EXPRESSION)
#define MPMM_UNREACHABLE abort()
#else
#define MPMM_INVARIANT(EXPRESSION) MPMM_ASSUME(EXPRESSION)
#define MPMM_UNREACHABLE MPMM_ASSUME(0)
#endif
#else
#error "MPMM: UNSUPPORTED COMPILER"
#endif



namespace mpmm
{
	template <typename T, typename U = T>
	MPMM_INLINE_ALWAYS void non_atomic_store(std::atomic<T>& where, U&& value) noexcept
	{
		static_assert(where.is_always_lock_free);
		*(T*)&where = value;
	}

	template <typename T>
	MPMM_INLINE_ALWAYS T non_atomic_load(const std::atomic<T>& from) noexcept
	{
		static_assert(from.is_always_lock_free);
		return *(const T*)&from;
	}

	template <typename T>
	MPMM_INLINE_ALWAYS constexpr bool bit_test(T mask, uint_fast8_t index) noexcept
	{
		return (mask & ((T)1 << (T)index)) != (T)0;
	}

	template <typename T>
	MPMM_INLINE_ALWAYS constexpr void bit_set(T& mask, uint_fast8_t index) noexcept
	{
		mask |= ((T)1 << index);
	}

	template <typename T>
	MPMM_INLINE_ALWAYS constexpr void bit_reset(T& mask, uint_fast8_t index) noexcept
	{
		mask &= (T)~((T)1 << index);
	}

	MPMM_INLINE_ALWAYS uint8_t find_first_set(uint32_t mask) noexcept
	{
		MPMM_INVARIANT(mask != 0);
		unsigned long r;
		(void)BitScanForward(&r, mask);
		return (uint8_t)r;
	}

	MPMM_INLINE_ALWAYS uint8_t find_first_set(uint64_t mask) noexcept
	{
		MPMM_INVARIANT(mask != 0);
		unsigned long r;
		(void)BitScanForward64(&r, mask);
		return (uint8_t)r;
	}

	MPMM_INLINE_ALWAYS uint8_t find_last_set(uint32_t mask) noexcept
	{
		MPMM_INVARIANT(mask != 0);
		unsigned long r;
		(void)BitScanReverse(&r, mask);
		return (uint8_t)r;
	}

	MPMM_INLINE_ALWAYS uint8_t find_last_set(uint64_t mask) noexcept
	{
		MPMM_INVARIANT(mask != 0);
		unsigned long r;
		(void)BitScanReverse64(&r, mask);
		return (uint8_t)r;
	}

	MPMM_INLINE_ALWAYS uint8_t floor_log2(uint32_t value) noexcept
	{
		return find_last_set(value);
	}

	MPMM_INLINE_ALWAYS uint8_t floor_log2(uint64_t value) noexcept
	{
		return find_last_set(value);
	}

	MPMM_INLINE_ALWAYS uint32_t round_pow2(uint32_t value) noexcept
	{
		if (MPMM_POPCOUNT32(value) == 1)
			return value;
		return 1UI32 << (floor_log2(value) + 1);
	}

	MPMM_INLINE_ALWAYS uint64_t round_pow2(uint64_t value) noexcept
	{
		if (MPMM_POPCOUNT64(value) == 1)
			return value;
		return 1UI64 << (floor_log2(value) + 1);
	}

	MPMM_INLINE_ALWAYS size_t wellons_hash(size_t value) noexcept
	{
		// Chris Wellons hash32 & hash64 https://nullprogram.com/blog/2018/07/31/

#if UINT32_MAX == UINTPTR_MAX
		value ^= value >> 16;
		value *= 0x45d9f3bUI32;
		value ^= value >> 16;
		value *= 0x45d9f3bUI32;
		value ^= value >> 16;
#else
		value ^= value >> 32;
		value *= 0xd6e8feb86659fd93UI64;
		value ^= value >> 32;
		value *= 0xd6e8feb86659fd93UI64;
		value ^= value >> 32;
#endif
		return value;
	}

	namespace params
	{
		constexpr uint32_t SMALL_SIZE_CLASSES[] =
		{
			1, 2, //Q=1
			4, 8, 12, 16, // Q=4
			32, 40, 48, 56, 64, // Q=8
			80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, // Q=16
			320, 352, 384, 416, 448, 480, 512, // Q=32
			576, 640, 704, 768, 832, 896, 960, 1024, // Q=64,
			1152, 1280, 1408, 1536, 1664, 1792, 1920, 2048, //Q=128
			2304, 2560, 2816, 3072, 3328, 3584, 3840, 4096 //Q=256
		};

		constexpr size_t SIZE_CLASS_COUNT = sizeof(SMALL_SIZE_CLASSES) / sizeof(SMALL_SIZE_CLASSES[0]);
		constexpr size_t BLOCK_ALLOCATOR_MAX_CAPACITY = std::hardware_constructive_interference_size * 8;
		constexpr size_t BLOCK_ALLOCATOR_MASK_COUNT = BLOCK_ALLOCATOR_MAX_CAPACITY / 64;

		inline size_t processor_count;
		inline size_t page_size;
		inline size_t chunk_size;
		inline uint8_t page_size_log2;
		inline uint8_t chunk_size_log2;
		inline size_t small_cache_size;
	}

	MPMM_INLINE_ALWAYS size_t chunk_size_of(size_t size) noexcept
	{
		size *= params::BLOCK_ALLOCATOR_MAX_CAPACITY;
		if (size > params::chunk_size)
			size = params::chunk_size;
		size = round_pow2(size);
		return size;
	}

#ifdef MPMM_WINDOWS
	namespace os
	{
		using thread_id = DWORD;

		inline void* min_chunk;
		inline void* max_address;
		inline const HANDLE process_handle = GetCurrentProcess();
		inline decltype(VirtualAlloc2)* aligned_allocate;
		inline uint64_t qpc_frequency;

		MPMM_INLINE_ALWAYS void init() noexcept
		{
			SYSTEM_INFO info;
			GetSystemInfo(&info);
			params::processor_count = info.dwNumberOfProcessors;
			params::page_size = info.dwPageSize;
			params::chunk_size = info.dwPageSize * std::hardware_constructive_interference_size * 8;
			constexpr size_t min_chunk_size = 32 * 4096;
			MPMM_INVARIANT(params::chunk_size >= min_chunk_size);
			params::page_size_log2 = floor_log2(params::page_size);
			params::chunk_size_log2 = floor_log2(params::chunk_size);
			max_address = info.lpMaximumApplicationAddress;
			min_chunk = (void*)MPMM_ALIGN_ROUND((size_t)info.lpMinimumApplicationAddress, params::chunk_size);
			HMODULE m = GetModuleHandle(TEXT("KernelBase.DLL"));
			MPMM_INVARIANT(m != NULL);
			aligned_allocate = (decltype(VirtualAlloc2)*)GetProcAddress(m, "VirtualAlloc2");
			LARGE_INTEGER k;
			(void)QueryPerformanceFrequency(&k);
			qpc_frequency = k.QuadPart;
		}

		MPMM_INLINE_ALWAYS void* allocate(size_t size) noexcept
		{
			return VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		}

		MPMM_INLINE_ALWAYS void* allocate_chunk_aligned(size_t size) noexcept
		{
			MEM_ADDRESS_REQUIREMENTS req = {};
			req.Alignment = params::chunk_size;
			req.HighestEndingAddress = max_address;
			req.LowestStartingAddress = min_chunk;
			MEM_EXTENDED_PARAMETER param = {};
			param.Type = MemExtendedParameterAddressRequirements;
			param.Pointer = &req;
			return aligned_allocate(process_handle, nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &param, 1);
		}

		MPMM_INLINE_ALWAYS void deallocate(void* ptr, size_t size) noexcept
		{
			MPMM_INVARIANT(ptr != nullptr);
			bool result = VirtualFree(ptr, 0, MEM_RELEASE);
			MPMM_INVARIANT(result);
		}

		MPMM_INLINE_ALWAYS void purge(void* ptr, size_t size) noexcept
		{
			MPMM_INVARIANT(ptr != nullptr);
			(void)DiscardVirtualMemory(ptr, size);
		}

		MPMM_INLINE_ALWAYS void make_readwrite(void* ptr, size_t size) noexcept
		{
			MPMM_INVARIANT(ptr != nullptr);
			DWORD old;
			(void)VirtualProtect(ptr, size, PAGE_READWRITE, &old);
		}

		MPMM_INLINE_ALWAYS void make_readonly(void* ptr, size_t size) noexcept
		{
			MPMM_INVARIANT(ptr != nullptr);
			DWORD old;
			(void)VirtualProtect(ptr, size, PAGE_READONLY, &old);
		}

		MPMM_INLINE_ALWAYS void make_noaccess(void* ptr, size_t size) noexcept
		{
			MPMM_INVARIANT(ptr != nullptr);
			DWORD old;
			(void)VirtualProtect(ptr, size, PAGE_READWRITE, &old);
		}

		MPMM_INLINE_ALWAYS uint32_t this_thread_id() noexcept
		{
			return GetCurrentThreadId();
		}

		MPMM_INLINE_ALWAYS uint32_t this_processor_index() noexcept
		{
			PROCESSOR_NUMBER pn;
			GetCurrentProcessorNumberEx(&pn);
			return (pn.Group << 6) | pn.Number;
		}

		MPMM_INLINE_ALWAYS bool does_thread_exist(thread_id id) noexcept
		{
			HANDLE thread = OpenThread(SYNCHRONIZE, false, id);
			if (thread == nullptr)
				return false;
			DWORD code = WaitForSingleObject(thread, 0);
			MPMM_INVARIANT(code != WAIT_FAILED);
			return code == WAIT_TIMEOUT;
		}
	}
#endif



	namespace backend
	{
		namespace callbacks
		{
			inline void (*init)() = os::init;
			inline void* (*allocate)(size_t size) = os::allocate;
			inline void* (*allocate_chunk_aligned)(size_t size) = os::allocate_chunk_aligned;
			inline void (*deallocate)(void* ptr, size_t size) = os::deallocate;
			inline void (*purge)(void* ptr, size_t size) = os::purge;
			inline void (*make_readwrite)(void* ptr, size_t size) = os::make_readwrite;
			inline void (*make_readonly)(void* ptr, size_t size) = os::make_readonly;
			inline void (*make_noaccess)(void* ptr, size_t size) = os::make_noaccess;
		}

		MPMM_INLINE_ALWAYS void init() noexcept
		{
			if (callbacks::init != nullptr)
				callbacks::init();
		}

		MPMM_INLINE_ALWAYS void* allocate(size_t size) noexcept
		{
			if (callbacks::allocate == nullptr)
				return nullptr;
			return callbacks::allocate(size);
		}

		MPMM_INLINE_ALWAYS void* allocate_chunk_aligned(size_t size) noexcept
		{
			if (callbacks::allocate_chunk_aligned == nullptr)
				return nullptr;
			return callbacks::allocate_chunk_aligned(size);
		}

		MPMM_INLINE_ALWAYS void deallocate(void* ptr, size_t size) noexcept
		{
			if (callbacks::deallocate != nullptr)
				callbacks::deallocate(ptr, size);
		}

		MPMM_INLINE_ALWAYS void purge(void* ptr, size_t size) noexcept
		{
			if (callbacks::purge != nullptr)
				callbacks::purge(ptr, size);
		}

		MPMM_INLINE_ALWAYS void make_readwrite(void* ptr, size_t size) noexcept
		{
			if (callbacks::make_readwrite != nullptr)
				callbacks::make_readwrite(ptr, size);
		}

		MPMM_INLINE_ALWAYS void make_readonly(void* ptr, size_t size) noexcept
		{
			if (callbacks::make_readonly != nullptr)
				callbacks::make_readonly(ptr, size);
		}

		MPMM_INLINE_ALWAYS void make_noaccess(void* ptr, size_t size) noexcept
		{
			if (callbacks::make_noaccess != nullptr)
				callbacks::make_noaccess(ptr, size);
		}
	}



	namespace romu2jr
	{
		static void init(uint64_t seed, uint64_t& x, uint64_t& y) noexcept
		{
			x = seed ^ 0x9e3779b97f4a7c15;
			y = seed ^ 0xd1b54a32d192ed03;
		}

		static uint64_t next(uint64_t& x, uint64_t& y) noexcept
		{
			uint64_t result = x;
			x = 15241094284759029579u * y;
			y = y - result;
			y = MPMM_ROL64(y, 27);
			return result;
		}
	}



	struct free_list_node
	{
		free_list_node* next;
	};

	struct free_list
	{
		free_list_node* head;

		MPMM_INLINE_ALWAYS void push(void* ptr) noexcept
		{
			free_list_node* nh = (free_list_node*)ptr;
			nh->next = head;
			head = nh;
		}

		MPMM_INLINE_ALWAYS void* pop() noexcept
		{
			void* r = head;
			if (r != nullptr)
				head = head->next;
			return r;
		}

		MPMM_INLINE_ALWAYS void* peek() noexcept
		{
			return head;
		}
	};

	struct recovered_list
	{
		std::atomic<free_list_node*> head;

		MPMM_INLINE_ALWAYS void push(void* ptr) noexcept
		{
			free_list_node* new_head = (free_list_node*)ptr;
			free_list_node* prior = head.exchange(new_head, std::memory_order_acquire);
			new_head->next = prior;
			std::atomic_thread_fence(std::memory_order_release);
		}

		MPMM_INLINE_ALWAYS void* peek() noexcept
		{
			return head.load(std::memory_order_acquire);
		}

		MPMM_INLINE_ALWAYS free_list_node* pop_all() noexcept
		{
			return head.exchange(nullptr, std::memory_order_acquire);
		}
	};

	struct shared_chunk_list
	{
		std::atomic<size_t> head;

		MPMM_INLINE_ALWAYS void push(void* ptr) noexcept
		{
			size_t counter_mask = params::chunk_size - 1;
			size_t pointer_mask = ~counter_mask;

			free_list_node* new_head = (free_list_node*)ptr;

			for (;; MPMM_SPIN_WAIT)
			{
				size_t prior = head.load(std::memory_order_acquire);
				free_list_node* prior_head = (free_list_node*)(prior & pointer_mask);
				new_head->next = prior_head;
				size_t counter = prior;
				++counter;
				counter &= counter_mask;
				size_t desired = (size_t)new_head;
				desired |= counter;
				if (head.compare_exchange_weak(prior, desired, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
		}

		MPMM_INLINE_ALWAYS void* pop() noexcept
		{
			size_t counter_mask = params::chunk_size - 1;
			size_t pointer_mask = ~counter_mask;
			for (;; MPMM_SPIN_WAIT)
			{
				size_t prior = head.load(std::memory_order_acquire);
				free_list_node* prior_head = (free_list_node*)(prior & pointer_mask);
				if (prior_head == nullptr)
					return nullptr;
				free_list_node* new_head = prior_head->next;
				size_t counter = prior;
				++counter;
				counter &= counter_mask;
				size_t desired = (size_t)new_head;
				desired |= counter;
				if (head.compare_exchange_weak(prior, desired, std::memory_order_acquire, std::memory_order_relaxed))
					return prior_head;
			}
		}

		MPMM_INLINE_ALWAYS void* peek() noexcept
		{
			size_t counter_mask = params::chunk_size - 1;
			size_t pointer_mask = ~counter_mask;
			size_t prior = head.load(std::memory_order_acquire);
			prior &= pointer_mask;
			return (void*)prior;
		}
	};

	struct shared_block_allocator_recover_list
	{
		struct head_type
		{
			free_list_node* head;
			size_t generation;
		};

		std::atomic<head_type> head;

		MPMM_INLINE_ALWAYS void push(void* new_head) noexcept
		{
			head_type prior, desired;
			desired.head = (free_list_node*)new_head;
			for (;; MPMM_SPIN_WAIT)
			{
				prior = head.load(std::memory_order_acquire);
				desired.head->next = prior.head;
				desired.generation = prior.generation + 1;
				if (head.compare_exchange_weak(prior, desired, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
		}

		MPMM_INLINE_ALWAYS void* pop() noexcept
		{
			head_type prior, desired;
			for (;; MPMM_SPIN_WAIT)
			{
				prior = head.load(std::memory_order_acquire);
				if (prior.head == nullptr)
					break;
				desired.head = prior.head->next;
				desired.generation = prior.generation + 1;
				if (head.compare_exchange_weak(prior, desired, std::memory_order_acquire, std::memory_order_relaxed))
					break;
			}
			return prior.head;
		}
	};



	namespace chunk_cache
	{
		struct MPMM_SHARED_ATTR chunk_cache_shard
		{
			static constexpr size_t GROUP_CAPACITY = sizeof(size_t) == sizeof(uint32_t) ? 11 : 7;

			using group_mask_type =
				std::conditional_t<GROUP_CAPACITY <= 8, uint8_t,
				std::conditional_t<GROUP_CAPACITY <= 16, uint16_t,
				std::conditional_t<GROUP_CAPACITY <= 32, uint32_t, uint64_t>>>;

			struct group_ctrl
			{
				group_mask_type count;
				uint8_t hints[GROUP_CAPACITY];
			};

			struct MPMM_SHARED_ATTR group_type
			{
				std::atomic<group_ctrl> ctrl;
				std::atomic<size_t> keys[GROUP_CAPACITY];
			};

			std::shared_mutex lock;
			group_type* groups;
			shared_chunk_list* values;
			size_t group_capacity_mask;
			std::atomic<size_t> count;

			bool should_expand() const noexcept
			{
				if (groups == nullptr)
					return true;
				size_t k = count.load(std::memory_order_acquire);
				size_t c = group_capacity_mask + 1;
				c *= GROUP_CAPACITY;
				c *= 7;
				c /= 8;
				return k >= c;
			}

			void init_empty() noexcept
			{
				new (this) chunk_cache_shard();
				groups = nullptr;
			}

			void init(size_t group_count) noexcept
			{
				new (this) chunk_cache_shard();
				size_t value_count = group_count * GROUP_CAPACITY;
				size_t k = sizeof(group_type) * group_count + sizeof(shared_chunk_list) * value_count;
				groups = (group_type*)backend::allocate(k);
				values = (shared_chunk_list*)(groups + group_count);
				group_capacity_mask = group_count - 1;
			}

			void expand_no_lock() noexcept
			{
				if (groups == nullptr)
					return init(1);
				chunk_cache_shard nt = {};
				nt.init((group_capacity_mask + 1) * 2);
				// copy
				groups = nt.groups;
				values = nt.values;
				group_capacity_mask = nt.group_capacity_mask;
			}

			void expand() noexcept
			{
				lock.unlock_shared();
				lock.lock();
				expand_no_lock();
				lock.unlock();
				lock.lock_shared();
			}

			void* allocate_no_lock(size_t size, size_t hash) noexcept
			{
				if (groups == nullptr)
					return nullptr;
				uint8_t hint = (uint8_t)hash;
				hash >>= 8;
				while (true)
				{
					hash &= group_capacity_mask;
					group_type& group = groups[hash];
					group_ctrl prior = group.ctrl.load(std::memory_order_acquire);
					while (true)
					{
						for (uint8_t i = 0; i != prior.count; ++i)
							if (prior.hints[i] == hint)
								if (group.keys[i].load(std::memory_order_acquire) == size)
									return values[i + hash * GROUP_CAPACITY].pop();
						group_ctrl new_ctrl = group.ctrl.load(std::memory_order_acquire);
						if (!memcmp(&prior, &new_ctrl, sizeof(group_ctrl)))
							break;
						prior = new_ctrl;
					}
					if (prior.count != GROUP_CAPACITY)
						return nullptr;
				}
			}

			void deallocate_no_lock(void* ptr, size_t size, size_t hash) noexcept
			{
				if (should_expand())
					expand();
				uint8_t hint = (uint8_t)hash;
				hash >>= 8;
				hash &= group_capacity_mask;
				while (true)
				{
					hash &= group_capacity_mask;
					group_type& group = groups[hash];
					while (true)
					{
						group_ctrl prior = group.ctrl.load(std::memory_order_acquire);
						group_ctrl desired;
						for (uint8_t i = 0; i != prior.count; ++i)
							if (prior.hints[i] == hint)
								if (group.keys[i].load(std::memory_order_acquire) == size)
									return values[i + hash * GROUP_CAPACITY].push(ptr);
						if (prior.count != GROUP_CAPACITY)
						{
							desired = prior;
							desired.hints[prior.count] = hint;
							desired.count = prior.count + 1;
							if (!group.ctrl.compare_exchange_weak(prior, desired, std::memory_order_acquire, std::memory_order_relaxed))
								continue;
							group.keys[prior.count].store(size, std::memory_order_release);
							values[prior.count + GROUP_CAPACITY * hash].push(ptr);
							(void)count.fetch_add(1, std::memory_order_release);
							return;
						}
						else
						{
							group_ctrl new_ctrl = group.ctrl.load(std::memory_order_acquire);
							if (!memcmp(&prior, &new_ctrl, sizeof(group_ctrl)))
								break;
							prior = new_ctrl;
						}
					}
				}
			}

			void* allocate(size_t size, size_t hash) noexcept
			{
				lock.lock_shared();
				void* const r = allocate_no_lock(size, hash);
				lock.unlock_shared();
				return r;
			}

			void deallocate(void* ptr, size_t size, size_t hash) noexcept
			{
				lock.lock_shared();
				deallocate_no_lock(ptr, size, hash);
				lock.unlock_shared();
			}
		};

		static shared_chunk_list single_chunk_bin;

		static constexpr uint8_t SHARD_COUNT_LOG2 = 8;
		static constexpr size_t SHARD_MASK = 255;
		static chunk_cache_shard shards[256];

		void init() noexcept
		{
			for (chunk_cache_shard& e : shards)
				e.init_empty();
		}

		void finalize() noexcept
		{
		}

		void* try_allocate(size_t size) noexcept
		{
			size >>= params::chunk_size_log2;
			if (size == 1)
				return single_chunk_bin.pop();
			--size;
			size_t hash = wellons_hash(size);
			size_t shard_index = hash & SHARD_MASK;
			hash >>= SHARD_COUNT_LOG2;
			return shards[shard_index].allocate(size, hash);
		}

		void* allocate(size_t size) noexcept
		{
			void* r = try_allocate(size);
			if (r == nullptr)
				r = backend::allocate_chunk_aligned(MPMM_ALIGN_ROUND(size, params::chunk_size));
			return r;
		}

		void deallocate(void* ptr, size_t size) noexcept
		{
			size >>= params::chunk_size_log2;
			if (size == 1)
				return single_chunk_bin.push(ptr);
			--size;
			size_t hash = wellons_hash(size);
			size_t shard_index = hash & SHARD_MASK;
			hash >>= SHARD_COUNT_LOG2;
			return shards[shard_index].deallocate(ptr, size, hash);
		}

		size_t block_size_of(size_t size) noexcept
		{
			size_t r = MPMM_ALIGN_ROUND(size, params::chunk_size);
			if (r < params::chunk_size)
				r = 0;
			return r;
		}

		size_t trim() noexcept
		{
			return 0;
		}

		size_t purge() noexcept
		{
			return 0;
		}
	}



	namespace shared_cache
	{
		struct MPMM_SHARED_ATTR shared_block_allocator
		{
			shared_block_allocator* next;
			shared_block_allocator_recover_list* recovered;
			uint8_t* buffer;
			uint32_t capacity;
			uint8_t block_size_log2;
			std::atomic<uint32_t> begin_free_mask;
			std::atomic<uint32_t> free_count;
			std::atomic_bool unlinked;
			MPMM_SHARED_ATTR std::atomic<uint64_t> free_map[params::BLOCK_ALLOCATOR_MASK_COUNT];

			MPMM_INLINE_ALWAYS void init(uint8_t block_size_log2, shared_block_allocator_recover_list* recovered, uint8_t* buffer) noexcept
			{
				this->next = nullptr;
				this->recovered = recovered;
				this->buffer = buffer;
				capacity = (uint32_t)(params::chunk_size >> block_size_log2);
				non_atomic_store(free_count, capacity);
				this->block_size_log2 = block_size_log2;
				non_atomic_store(unlinked, false);
				(void)memset(free_map, 0, sizeof(free_map));
				uint32_t mask_count = capacity >> 6;
				uint32_t bit_count = capacity & 63;
				if (mask_count != 0)
					memset(free_map, 0xff, mask_count * sizeof(uint64_t));
				if (bit_count != 0)
					non_atomic_store(free_map[mask_count], (1UI64 << bit_count) - 1UI64);
			}

			MPMM_INLINE_ALWAYS uint32_t index_of(void* ptr) const noexcept
			{
				return ((uint32_t)((uint8_t*)ptr - buffer)) >> block_size_log2;
			}

			MPMM_INLINE_ALWAYS void* allocate() noexcept
			{
				while (true)
				{
					for (uint32_t i = 0; i != params::BLOCK_ALLOCATOR_MASK_COUNT; ++i)
					{
						if (free_count.load(std::memory_order_acquire) == 0)
							return nullptr;

						for (;; MPMM_SPIN_WAIT)
						{
							uint64_t prior = free_map[i].load(std::memory_order_acquire);
							if (prior == 0)
								break;
							uint8_t j = find_first_set(prior);
							uint64_t desired = prior;
							bit_reset(desired, j);
							if (free_map[i].compare_exchange_weak(prior, desired, std::memory_order_acquire, std::memory_order_relaxed))
							{
								(void)free_count.fetch_sub(1, std::memory_order_release);
								return buffer + (((i << 6) | j) << block_size_log2);
							}
						}
					}
				}
			}

			MPMM_INLINE_NEVER void recover() noexcept
			{
				bool expected = true;
				if (unlinked.compare_exchange_strong(expected, false, std::memory_order_acquire, std::memory_order_relaxed))
					recovered->push(this);
			}

			MPMM_INLINE_ALWAYS void deallocate(void* ptr) noexcept
			{
				uint32_t index = index_of(ptr);
				uint32_t mask_index = index >> 6;
				uint8_t bit_index = index & 63;
				(void)free_map[mask_index].fetch_or(1UI64 << bit_index, std::memory_order_release);
				(void)free_count.fetch_add(1, std::memory_order_relaxed);
				if (unlinked.load(std::memory_order_acquire))
					recover();
			}

			MPMM_INLINE_ALWAYS bool owns(void* ptr) noexcept
			{
				if ((uint8_t*)ptr < buffer)
					return false;
				if ((uint8_t*)ptr >= buffer + ((size_t)params::BLOCK_ALLOCATOR_MAX_CAPACITY << block_size_log2))
					return false;
				uint32_t index = index_of(ptr);
				uint32_t mask_index = index >> 6;
				uint8_t bit_index = index & 63;
				return bit_test(free_map[mask_index].load(std::memory_order_acquire), bit_index);
			}
		};

		struct MPMM_SHARED_ATTR shared_allocator_list
		{
			std::atomic<shared_block_allocator*> head;

			shared_block_allocator* peek() const noexcept
			{
				return head.load(std::memory_order_acquire);
			}

			MPMM_INLINE_ALWAYS void push(shared_block_allocator* new_head) noexcept
			{
				shared_block_allocator* prior;
				for (;; MPMM_SPIN_WAIT)
				{
					prior = head.load(std::memory_order_acquire);
					new_head->next = prior;
					if (head.compare_exchange_weak(prior, new_head, std::memory_order_release, std::memory_order_relaxed))
						break;
				}
			}

			MPMM_INLINE_ALWAYS void pop_if_equal(shared_block_allocator* expected) noexcept
			{
				if (head.compare_exchange_strong(expected, expected->next, std::memory_order_acquire, std::memory_order_relaxed))
					expected->unlinked.store(true, std::memory_order_release);
			}
		};



		static uint8_t size_class_count;
#if UINTPTR_MAX == UINT32_MAX
		static shared_block_allocator* chunk_lookup;
#else
		struct node_ptr
		{
			size_t mask;

			constexpr void set(const void* ptr, bool flag) noexcept
			{
				MPMM_INVARIANT(((size_t)ptr & 1) == 0);
				mask = (size_t)ptr | (size_t)flag;
			}

			template <typename T>
			constexpr T* ptr() const noexcept
			{
				return (T*)(mask & ~(size_t)1);
			}

			constexpr bool is_early_leaf() const noexcept
			{
				return mask & 1;
			}
		};

		struct MPMM_SHARED_ATTR shared_block_allocator_group
		{
			std::atomic<uint64_t> presence[8];
			shared_block_allocator allocators[256];
		};

		static size_t branch_size_mask;
		static uint8_t branch_size_log2;
		static std::atomic<std::atomic<shared_block_allocator_group*>*> chunk_lookup_roots[65536];

		static shared_block_allocator* register_allocator(size_t id) noexcept
		{
			uint16_t root_index = id & 65535;
			id >>= 16;
			uint32_t middle_index = (uint32_t)(id & branch_size_mask);
			id >>= branch_size_log2;
			uint8_t leaf_index = (uint8_t)id;
			MPMM_INVARIANT((id >> 8) == 0);
			auto& root = chunk_lookup_roots[root_index];
			std::atomic<shared_block_allocator_group*>* branch;
			for (std::atomic<shared_block_allocator_group*>* tmp = nullptr;; MPMM_SPIN_WAIT)
			{
				branch = root.load(std::memory_order_acquire);
				if (branch != nullptr)
				{
					if (tmp != nullptr)
						backend::deallocate(tmp, branch_size_mask + 1);
					break;
				}
				if (tmp == nullptr)
					tmp = (std::atomic<shared_block_allocator_group*>*)backend::allocate_chunk_aligned(branch_size_mask + 1);
				if (root.compare_exchange_weak(branch, tmp, std::memory_order_acquire, std::memory_order_relaxed))
				{
					branch = tmp;
					break;
				}
			}
			std::atomic<shared_block_allocator_group*>& leaf_ptr = branch[middle_index];
			shared_block_allocator_group* leaf;
			for (shared_block_allocator_group* tmp = nullptr;; MPMM_SPIN_WAIT)
			{
				leaf = leaf_ptr.load(std::memory_order_acquire);
				if (leaf != nullptr)
				{
					if (tmp != nullptr)
						backend::deallocate(tmp, branch_size_mask + 1);
					break;
				}
				if (tmp == nullptr)
					tmp = (shared_block_allocator_group*)backend::allocate_chunk_aligned(sizeof(shared_block_allocator_group));
				if (leaf_ptr.compare_exchange_weak(leaf, tmp, std::memory_order_acquire, std::memory_order_relaxed))
				{
					leaf = tmp;
					break;
				}
			}
			uint8_t leaf_mask_index = leaf_index >> 6;
			uint8_t leaf_bit_index = leaf_index & 63;
			uint64_t prior = leaf->presence[leaf_mask_index].fetch_or(1UI64 << leaf_bit_index, std::memory_order_acquire);
			MPMM_INVARIANT(!bit_test(prior, leaf_bit_index));
			return &leaf->allocators[leaf_index];
		}

		static shared_block_allocator* find_allocator(size_t id) noexcept
		{
			uint16_t root_index = id & 65535;
			id >>= 16;
			uint32_t middle_index = (uint32_t)(id & branch_size_mask);
			id >>= branch_size_log2;
			uint8_t leaf_index = (uint8_t)id;
			std::atomic<shared_block_allocator_group*>* branch = chunk_lookup_roots[root_index].load(std::memory_order_acquire);
			if (branch == nullptr)
				return nullptr;
			shared_block_allocator_group* leaf = branch[middle_index].load(std::memory_order_acquire);
			if (leaf == nullptr)
				return nullptr;
			uint8_t leaf_mask_index = leaf_index >> 6;
			uint8_t leaf_bit_index = leaf_index & 63;
			if (!bit_test(leaf->presence[leaf_mask_index].load(std::memory_order_acquire), leaf_bit_index))
				return nullptr;
			return &leaf->allocators[leaf_index];
		}

		static void deregister_allocator(size_t id) noexcept
		{
			uint16_t root_index = id & 65535;
			id >>= 16;
			uint32_t middle_index = (uint32_t)(id & branch_size_mask);
			id >>= branch_size_log2;
			uint8_t leaf_index = (uint8_t)id;
			std::atomic<shared_block_allocator_group*>* branch = chunk_lookup_roots[root_index].load(std::memory_order_acquire);
			MPMM_INVARIANT(branch != nullptr);
			shared_block_allocator_group* leaf = branch[middle_index].load(std::memory_order_acquire);
			MPMM_INVARIANT(leaf != nullptr);
			uint8_t leaf_mask_index = leaf_index >> 6;
			uint8_t leaf_bit_index = leaf_index & 63;
			uint64_t prior = leaf->presence[leaf_mask_index].fetch_and(~(1UI64 << leaf_bit_index), std::memory_order_release);
			MPMM_INVARIANT(bit_test(prior, leaf_bit_index));
		}
#endif

		shared_allocator_list* bins;
		shared_block_allocator_recover_list* recovered;

		MPMM_INLINE_ALWAYS static size_t chunk_id_of(void* data) noexcept
		{
			size_t mask = (size_t)data;
			mask >>= params::chunk_size_log2;
			return mask;
		}

		void init() noexcept
		{
			size_class_count = params::chunk_size_log2 - params::page_size_log2;
			size_t buffer_size = 0;
#if UINTPTR_MAX == UINT32_MAX
			size_t chunk_count = 1U << (32 - params::chunk_size_log2);
			buffer_size += chunk_count * sizeof(shared_block_allocator);
#else
			branch_size_log2 = 64 - params::chunk_size_log2 - 24;
			branch_size_mask = (sizeof(std::atomic<std::atomic<shared_block_allocator_group>*>) << branch_size_log2) - 1;
#endif
			buffer_size += size_class_count * sizeof(shared_allocator_list);
			buffer_size += size_class_count * sizeof(shared_block_allocator_recover_list);
			uint8_t* buffer = (uint8_t*)backend::allocate(buffer_size);
#if UINTPTR_MAX == UINT32_MAX
			chunk_lookup = (shared_block_allocator*)buffer;
			buffer += chunk_count * sizeof(shared_block_allocator);
#endif
			bins = (shared_allocator_list*)buffer;
			buffer += size_class_count * sizeof(shared_allocator_list);
			recovered = (shared_block_allocator_recover_list*)buffer;
		}

		void finalize() noexcept
		{
#if UINTPTR_MAX == UINT32_MAX
#else
#endif
		}

		static void* try_allocate_impl(uint8_t sc) noexcept
		{
			shared_block_allocator* allocator;
			while (true)
			{
				shared_block_allocator* allocator = bins[sc].peek();
				if (allocator == nullptr)
					break;
				void* r = allocator->allocate();
				if (r != nullptr)
					return r;
				if (allocator->free_count.load(std::memory_order_acquire) == 0)
					bins[sc].pop_if_equal(allocator);
			}
			allocator = (shared_block_allocator*)recovered[sc].pop();
			if (allocator == nullptr)
				return nullptr;
			void* r = allocator->allocate();
			MPMM_INVARIANT(r != nullptr);
			bins[sc].push(allocator);
			return r;
		}

		void* try_allocate(size_t size) noexcept
		{
			uint8_t sc = floor_log2(size) - params::page_size_log2;
			return try_allocate_impl(sc);
		}

		void* allocate(size_t size) noexcept
		{
			uint8_t size_log2 = floor_log2(size);
			uint8_t sc = floor_log2(size) - params::page_size_log2;
			void* r = try_allocate_impl(sc);
			if (r == nullptr)
			{
				uint8_t* buffer = (uint8_t*)chunk_cache::allocate(params::chunk_size);
				shared_block_allocator* allocator;
				size_t id = chunk_id_of(buffer);
#if UINTPTR_MAX == UINT32_MAX
				allocator = &chunk_lookup[id];
#else
				allocator = register_allocator(id);
#endif
				allocator->init(size_log2, recovered + sc, buffer);
				r = allocator->allocate();
				bins[sc].push(allocator);
			}
			return r;
		}

		void deallocate(void* ptr, size_t size) noexcept
		{
			size_t id = chunk_id_of(ptr);
#if UINTPTR_MAX == UINT32_MAX
			chunk_lookup[id].deallocate(ptr);
#else
			find_allocator(id)->deallocate(ptr);
#endif
		}

		size_t block_size_of(size_t size) noexcept
		{
			return round_pow2(size);
		}

		size_t trim() noexcept
		{
			return 0;
		}

		size_t purge() noexcept
		{
			return 0;
		}
	}



	namespace thread_cache
	{
		struct MPMM_SHARED_ATTR intrusive_block_allocator
		{
			intrusive_block_allocator* next;
			recovered_list* recovered;
			uint32_t free_count;
			uint32_t begin_free_mask;
			uint32_t block_size;
			uint32_t capacity;
			std::atomic<os::thread_id> owning_thread;
			std::atomic_bool unlinked;
			MPMM_SHARED_ATTR uint64_t free_map[params::BLOCK_ALLOCATOR_MASK_COUNT];
			MPMM_SHARED_ATTR std::atomic<uint64_t> marked_map[params::BLOCK_ALLOCATOR_MASK_COUNT];

			MPMM_INLINE_ALWAYS void init(uint32_t block_size, size_t chunk_size, recovered_list* recovered) noexcept
			{
				this->next = nullptr;
				this->recovered = recovered;
				capacity = (uint32_t)(chunk_size / block_size);
				uint32_t reserved_count = (uint32_t)MPMM_ALIGN_ROUND(sizeof(intrusive_block_allocator), (size_t)block_size) / block_size;
				free_count = capacity - reserved_count;
				begin_free_mask = 0;
				this->block_size = block_size;
				non_atomic_store(unlinked, false);
				(void)memset(free_map, 0, sizeof(free_map));
				(void)memset(marked_map, 0, sizeof(marked_map));
				uint32_t mask_count = capacity >> 6;
				uint32_t bit_count = capacity & 63;
				if (mask_count != 0)
					memset(free_map, 0xff, mask_count * sizeof(uint64_t));
				if (bit_count != 0)
					free_map[mask_count] = (1UI64 << bit_count) - 1UI64;
				mask_count = reserved_count >> 6;
				bit_count = reserved_count & 63;
				if (mask_count != 0)
					memset(free_map, 0, mask_count * sizeof(uint64_t));
				if (bit_count != 0)
					free_map[0] &= ~((1UI64 << bit_count) - 1UI64);
			}

			MPMM_INLINE_NEVER uint32_t reclaim() noexcept
			{
				uint32_t freed_count = 0;
				for (uint32_t i = 0; i != params::BLOCK_ALLOCATOR_MASK_COUNT; ++i)
				{
					if (marked_map[i].load(std::memory_order_acquire) != 0)
					{
						uint64_t mask = marked_map[i].exchange(0, std::memory_order_acquire);
						free_map[i] |= mask;
						freed_count += MPMM_POPCOUNT64(mask);
					}
				}
				return freed_count;
			}

			MPMM_INLINE_ALWAYS uint32_t index_of(void* ptr) const noexcept
			{
				return ((uint32_t)((uint8_t*)ptr - (uint8_t*)this)) / block_size;
			}

			MPMM_INLINE_ALWAYS void* allocate() noexcept
			{
				for (uint32_t mask_index = begin_free_mask; mask_index != params::BLOCK_ALLOCATOR_MASK_COUNT; ++mask_index)
				{
					if (free_map[mask_index] != 0)
					{
						if (begin_free_mask < mask_index)
							begin_free_mask = mask_index;
						uint32_t bit_index = find_first_set(free_map[mask_index]);
						bit_reset(free_map[mask_index], bit_index);
						uint32_t offset = (mask_index << 6) | bit_index;
						offset *= block_size;
						--free_count;
						if (free_count == 0)
							free_count += reclaim();
						return (uint8_t*)this + offset;
					}
				}
				MPMM_UNREACHABLE;
			}

			MPMM_INLINE_NEVER void final_recover(os::thread_id prior_owner) noexcept
			{
				if (owning_thread.compare_exchange_strong(prior_owner, os::this_thread_id(), std::memory_order_acquire, std::memory_order_relaxed))
				{
					reclaim();
					if (free_count == capacity)
						mpmm::deallocate(this, chunk_size_of(block_size));
				}
			}

			MPMM_INLINE_NEVER void recover() noexcept
			{
				os::thread_id prior_owner = owning_thread.load(std::memory_order_acquire);
				if (!os::does_thread_exist(prior_owner))
					return final_recover(prior_owner);
				bool expected = true;
				if (unlinked.compare_exchange_strong(expected, false, std::memory_order_acquire, std::memory_order_relaxed))
					recovered->push(this);
			}

			MPMM_INLINE_ALWAYS void deallocate(void* ptr) noexcept
			{
				++free_count;
				uint32_t index = index_of(ptr);
				uint32_t mask_index = index >> 6;
				uint32_t bit_index = index & 63;
				if (begin_free_mask < mask_index)
					begin_free_mask = mask_index;
				bit_set(free_map[mask_index], bit_index);
				if (unlinked.load(std::memory_order_acquire))
					recover();
			}

			MPMM_INLINE_ALWAYS void deallocate_shared(void* ptr) noexcept
			{
				uint32_t index = index_of(ptr);
				uint32_t mask_index = index >> 6;
				uint32_t bit_index = index & 63;
				(void)marked_map[mask_index].fetch_or(1UI64 << bit_index, std::memory_order_release);
				if (unlinked.load(std::memory_order_acquire))
					recover();
			}

			MPMM_INLINE_ALWAYS bool owns(void* ptr) noexcept
			{
				if ((uint8_t*)ptr < (uint8_t*)this)
					return false;
				if ((uint8_t*)ptr >= (uint8_t*)this + (size_t)params::BLOCK_ALLOCATOR_MAX_CAPACITY * block_size)
					return false;
				uint32_t index = index_of(ptr);
				uint32_t mask_index = index >> 6;
				uint32_t bit_index = index & 63;
				return bit_test(free_map[mask_index], bit_index);
			}

			MPMM_INLINE_ALWAYS
				static intrusive_block_allocator* allocator_of(void* ptr, size_t chunk_size) noexcept
			{
				size_t mask = (size_t)ptr;
				mask = MPMM_ALIGN_FLOOR(mask, chunk_size);
				return (intrusive_block_allocator*)mask;
			}
		};

		struct MPMM_SHARED_ATTR cache_aligned_recovered_list
		{
			recovered_list list;
		};

		struct thread_cache_state
		{
			free_list small_bins[params::SIZE_CLASS_COUNT];
			cache_aligned_recovered_list small_recovered[params::SIZE_CLASS_COUNT];
			free_list* large_bins;
			cache_aligned_recovered_list* large_recovered;
		};

		thread_local static thread_cache_state here;

		uint8_t size_class_of(size_t size) noexcept
		{
			for (uint8_t i = 0; i != params::SIZE_CLASS_COUNT; ++i)
				if (params::SMALL_SIZE_CLASSES[i] >= size)
					return i;
			MPMM_UNREACHABLE;
		}

		size_t block_size_of_unsafe(size_t size) noexcept
		{
			return params::SMALL_SIZE_CLASSES[size_class_of(size)];
		}

		size_t block_size_of(size_t size) noexcept
		{
			if (size == 0 || size > params::page_size)
				return 0;
			return block_size_of_unsafe(size);
		}

		MPMM_INLINE_NEVER
			static void* allocate_fallback(uint8_t sc) noexcept
		{
			cache_aligned_recovered_list& e = here.small_recovered[sc];
			intrusive_block_allocator* head = (intrusive_block_allocator*)e.list.pop_all();
			if (head == nullptr)
				return nullptr;
			MPMM_INVARIANT(head->free_count != 0);
			void* r = head->allocate();
			if (head->free_count == 0)
			{
				head->unlinked.store(true, std::memory_order_release);
				head = (intrusive_block_allocator*)head->next;
			}
			MPMM_INVARIANT(here.small_bins[sc].head == nullptr);
			here.small_bins[sc].head = (free_list_node*)head;
			return r;
		}

		void* try_allocate_impl(uint8_t sc) noexcept
		{
			free_list& bin = here.small_bins[sc];
			intrusive_block_allocator* head = (intrusive_block_allocator*)bin.peek();
			if (head == nullptr)
				return allocate_fallback(sc);
			MPMM_INVARIANT(head->free_count != 0);
			void* r = head->allocate();
			if (head->free_count == 0)
			{
				(void)bin.pop();
				head->unlinked.store(true, std::memory_order_release);
			}
			return r;
		}

		void* try_allocate(size_t size) noexcept
		{
			uint8_t sc = size_class_of(size);
			return try_allocate_impl(sc);
		}

		void* allocate(size_t size) noexcept
		{
#ifndef MPMM_NO_ZERO_SIZE_CHECK
			size |= (size == 0);
#endif
			uint8_t sc = size_class_of(size);
			void* r = try_allocate_impl(sc);
			if (r != nullptr)
				return r;
			size = block_size_of_unsafe(size);
			size_t chunk_size = chunk_size_of(size);
			intrusive_block_allocator* allocator = (intrusive_block_allocator*)mpmm::allocate(chunk_size);
			if (allocator == nullptr)
				return nullptr;
			allocator->init((uint32_t)size, chunk_size, &(here.small_recovered[sc].list));
			non_atomic_store(allocator->owning_thread, os::this_thread_id());
			MPMM_INVARIANT(allocator->free_count != 0);
			r = allocator->allocate();
			MPMM_INVARIANT(allocator->free_count != 0);
			here.small_bins[sc].push(allocator);
			return r;
		}

		void deallocate(void* ptr, size_t size) noexcept
		{
#ifndef MPMM_NO_ZERO_SIZE_CHECK
			size |= (size == 0);
#endif
			uint8_t sc = size_class_of(size);
			recovered_list* expected_recovered_list = &(here.small_recovered[sc].list);
			intrusive_block_allocator* allocator = intrusive_block_allocator::allocator_of(ptr, chunk_size_of(size));
			if (allocator->recovered == expected_recovered_list)
				allocator->deallocate(ptr);
			else
				allocator->deallocate_shared(ptr);
		}

		void init() noexcept
		{
		}

		void finalize() noexcept
		{
		}

		size_t trim() noexcept
		{
			return 0;
		}

		size_t purge() noexcept
		{
			return 0;
		}
	}

	void init() noexcept
	{
		backend::init();
		shared_cache::init();
		chunk_cache::init();
	}

	void finalize() noexcept
	{
		chunk_cache::finalize();
		shared_cache::finalize();
	}

	void init_thread() noexcept
	{
		thread_cache::init();
	}

	bool is_initialized_thread() noexcept
	{
		return true;
	}

	void finalize_thread() noexcept
	{
		thread_cache::finalize();
	}

	void* allocate(size_t size) noexcept
	{
		void* r;
		if (size <= params::page_size)
			r = thread_cache::allocate(size);
		else if (size < params::chunk_size)
			r = shared_cache::allocate(size);
		else
			r = chunk_cache::allocate(size);
#if defined(MPMM_DEBUG) && !defined(MPMM_NO_JUNK)
		(void)memset(r, MPMM_JUNK_VALUE, size);
#endif
		return r;
	}

	bool try_expand(void* ptr, size_t old_size, size_t new_size) noexcept
	{
		return block_size_of(old_size) >= new_size;
	}

	void* reallocate(void* ptr, size_t old_size, size_t new_size) noexcept
	{
		if (try_expand(ptr, old_size, new_size))
			return ptr;
		void* const r = allocate(new_size);
		if (r != nullptr)
		{
			(void)memcpy(r, ptr, old_size);
			deallocate(ptr, old_size);
		}
		return r;
	}

	void deallocate(void* ptr, size_t size) noexcept
	{
		if (size <= params::page_size)
			return thread_cache::deallocate(ptr, size);
		if (size < params::chunk_size)
			return shared_cache::deallocate(ptr, size);
		return chunk_cache::deallocate(ptr, size);
	}

	size_t block_size_of(size_t size) noexcept
	{
		if (size <= params::page_size)
			return thread_cache::block_size_of(size);
		if (size < params::chunk_size)
			return shared_cache::block_size_of(size);
		return chunk_cache::block_size_of(size);
	}

	size_t trim() noexcept
	{
		return 0;
	}

	size_t purge() noexcept
	{
		return 0;
	}
}
#endif