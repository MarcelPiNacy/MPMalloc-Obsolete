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

#ifndef MPMALLOC_INCLUDED
#define MPMALLOC_INCLUDED
#include <cstdint>



namespace mpmalloc
{
	namespace fn_ptr
	{
		using init = void(*)();
		using finalize = void(*)();
		using allocate = void* (*)(size_t);
		using allocate_chunk_aligned = void* (*)(size_t);
		using try_expand = bool (*)(void*, size_t, size_t);
		using reallocate = void* (*)(void*, size_t, size_t);
		using deallocate = void (*)(void*, size_t);
		using purge = deallocate;
		using protect_readwrite = deallocate;
		using protect_readonly = deallocate;
		using protect_noaccess = deallocate;
	}

	struct backend_options
	{
		fn_ptr::init init;
		fn_ptr::finalize finalize;
		fn_ptr::allocate allocate;
		fn_ptr::allocate_chunk_aligned allocate_chunk_aligned;
		fn_ptr::deallocate deallocate;
		fn_ptr::purge purge;
		fn_ptr::protect_readwrite protect_readwrite;
		fn_ptr::protect_readonly protect_readonly;
		fn_ptr::protect_noaccess protect_noaccess;
	};

	struct platform_information
	{
		size_t processor_count;
		size_t cache_line_size;
		size_t page_size;
		size_t large_page_size;
		size_t chunk_size;
		size_t address_space_granularity;
		void* min_address;
		void* max_address;
	};

	struct init_options
	{
		const backend_options* backend;
	};

	void init(const init_options* options = nullptr);
	void finalize();
	void init_thread();
	void finalize_thread();

	[[nodiscard]]
	void* allocate(size_t size);
	bool try_expand(void* ptr, size_t old_size, size_t new_size);
	[[nodiscard]]
	void* reallocate(void* ptr, size_t old_size, size_t new_size);
	void deallocate(void* ptr, size_t size);
	size_t block_size_of(size_t size);
	size_t trim();
	size_t purge();

	backend_options default_backend();
	backend_options current_backend();
	platform_information platform_info();

	namespace statistics
	{
		size_t used_physical_memory();
		size_t total_physical_memory();
		size_t used_address_space();
		size_t total_address_space();
	}

	namespace large_cache
	{
		[[nodiscard]]
		void* try_allocate(size_t size);
		[[nodiscard]]
		void* allocate(size_t size);
		void deallocate(void* ptr, size_t size);
		size_t block_size_of(size_t size);
		size_t trim();
		size_t purge();
	}

	namespace shared_cache
	{
		[[nodiscard]]
		void* try_allocate(size_t size);
		[[nodiscard]]
		void* allocate(size_t size);
		void deallocate(void* ptr, size_t size);
		size_t block_size_of(size_t size);
		size_t trim();
		size_t purge();
	}

	namespace thread_cache
	{
		[[nodiscard]]
		void* try_allocate(size_t size);
		[[nodiscard]]
		void* allocate(size_t size);
		void deallocate(void* ptr, size_t size);
		size_t block_size_of(size_t size);
		size_t trim();
		size_t purge();
	}
}
#endif



#ifdef MPMALLOC_IMPLEMENTATION
#include <new>
#include <atomic>

#if UINT32_MAX == UINTPTR_MAX
#define MPMALLOC_32BIT
#else
#define MPMALLOC_64BIT
#endif

#if !defined(MPMALLOC_DEBUG) && (defined(_DEBUG) || !defined(NDEBUG))
#define MPMALLOC_DEBUG
#endif

#if !defined(MPMALLOC_JUNK_VALUE) && !defined(MPMALLOC_NO_JUNK)
#define MPMALLOC_JUNK_VALUE 0xcd
#endif

#ifndef MPMALLOC_SHARED_ATTR
#define MPMALLOC_SHARED_ATTR alignas(std::hardware_destructive_interference_size)
#endif

#define MPMALLOC_ALIGN_FLOOR(VALUE, ALIGNMENT) ((VALUE) & ~((ALIGNMENT) - 1))
#define MPMALLOC_ALIGN_ROUND(VALUE, ALIGNMENT) ((VALUE + ((ALIGNMENT) - 1)) & ~((ALIGNMENT) - 1))
#define MPMALLOC_ALIGN_FLOOR_LOG2(VALUE, ALIGNMENT_LOG2) MPMALLOC_ALIGN_FLOOR(VALUE, ((size_t)1 << (size_t)ALIGNMENT_LOG2))
#define MPMALLOC_ALIGN_ROUND_LOG2(VALUE, ALIGNMENT_LOG2) MPMALLOC_ALIGN_ROUND(VALUE, ((size_t)1 << (size_t)ALIGNMENT_LOG2))

#ifdef _WIN32
#define MPMALLOC_WINDOWS
#include <Windows.h>
#include <intrin.h>
#define MPMALLOC_SPIN_WAIT YieldProcessor()
#else
#error "MPMALLOC: UNSUPPORTED OS"
#endif

#ifdef _MSVC_LANG
#define MPMALLOC_LIKELY_IF(CONDITION) if ((CONDITION))
#define MPMALLOC_UNLIKELY_IF(CONDITION) if ((CONDITION))
#ifdef MPMALLOC_32BIT
#define MPMALLOC_POPCOUNT(MASK) ((uint_fast8_t)__popcnt((MASK)))
#else
#define MPMALLOC_POPCOUNT(MASK) ((uint_fast8_t)__popcnt64((MASK)))
#endif
#define MPMALLOC_INLINE_ALWAYS __forceinline
#define MPMALLOC_INLINE_NEVER __declspec(noinline)
#define MPMALLOC_ASSUME(EXPRESSION) __assume(EXPRESSION)
#ifdef MPMALLOC_DEBUG
#include <cassert>
#define MPMALLOC_INVARIANT(EXPRESSION) assert(EXPRESSION)
#define MPMALLOC_UNREACHABLE abort()
#else
#define MPMALLOC_INVARIANT(EXPRESSION) MPMALLOC_ASSUME(EXPRESSION)
#define MPMALLOC_UNREACHABLE MPMALLOC_ASSUME(0)
#endif
#else
#error "MPMALLOC: UNSUPPORTED COMPILER"
#endif

namespace mpmalloc
{
	template <typename T, typename U = T>
	MPMALLOC_INLINE_ALWAYS static void non_atomic_store(std::atomic<T>& where, U&& value)
	{
		static_assert(std::atomic<T>::is_always_lock_free);
		new ((T*)&where) T(std::forward<U>(value));
	}

	template <typename T>
	MPMALLOC_INLINE_ALWAYS static T non_atomic_load(const std::atomic<T>& from)
	{
		static_assert(std::atomic<T>::is_always_lock_free);
		return *(const T*)&from;
	}

	template <typename T>
	MPMALLOC_INLINE_ALWAYS static constexpr bool bit_test(T mask, uint_fast8_t index)
	{
		return (mask & ((T)1 << (T)index)) != (T)0;
	}

	template <typename T>
	MPMALLOC_INLINE_ALWAYS static constexpr void bit_set(T& mask, uint_fast8_t index)
	{
		mask |= ((T)1 << index);
	}

	template <typename T>
	MPMALLOC_INLINE_ALWAYS static constexpr void bit_reset(T& mask, uint_fast8_t index)
	{
		mask &= (T)~((T)1 << index);
	}

	MPMALLOC_INLINE_ALWAYS static uint_fast8_t find_first_set(size_t mask)
	{
		MPMALLOC_INVARIANT(mask != 0);
		unsigned long r;
#ifdef MPMALLOC_64BIT
		(void)BitScanForward64(&r, mask);
#else
		(void)BitScanForward(&r, mask);
#endif
		return (uint_fast8_t)r;
	}

	MPMALLOC_INLINE_ALWAYS static uint_fast8_t find_last_set(size_t mask)
	{
		MPMALLOC_INVARIANT(mask != 0);
		unsigned long r;
#ifdef MPMALLOC_64BIT
		(void)BitScanReverse64(&r, mask);
#else
		(void)BitScanReverse(&r, mask);
#endif
		return (uint_fast8_t)r;
	}
	
	MPMALLOC_INLINE_ALWAYS static uint_fast8_t floor_log2(size_t value)
	{
		return find_last_set(value);
	}

	MPMALLOC_INLINE_ALWAYS static size_t round_pow2(size_t value)
	{
		return (size_t)1 << (floor_log2(value) + 1);
	}

	namespace params
	{
		static constexpr uint_fast16_t SMALL_SIZE_CLASSES[] =
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

#ifdef MPMALLOC_32BIT
		using mask_type = uint32_t;
#else
		using mask_type = uint64_t;
#endif
		static constexpr uint8_t BLOCK_MASK_BIT_SIZE_LOG2 = sizeof(mask_type) == 4 ? 5 : 6;
		static constexpr uint8_t BLOCK_MASK_MOD_MASK = (1UI8 << BLOCK_MASK_BIT_SIZE_LOG2) - 1UI8;

		static constexpr size_t SIZE_CLASS_COUNT = sizeof(SMALL_SIZE_CLASSES) / sizeof(SMALL_SIZE_CLASSES[0]);
		static constexpr size_t BLOCK_ALLOCATOR_MAX_CAPACITY = std::hardware_constructive_interference_size * 8;
		static constexpr size_t BLOCK_ALLOCATOR_MASK_COUNT = BLOCK_ALLOCATOR_MAX_CAPACITY / (4 * sizeof(mask_type));

		static void* min_chunk;
		static void* min_address;
		static void* max_address;
		static size_t processor_count;
		static size_t large_page_size;
		static size_t page_size;
		static size_t chunk_size;
		static size_t chunk_size_mask;
		static size_t small_cache_size;
		static size_t vas_granularity;
#ifdef MPMALLOC_64BIT
		static constexpr uint8_t CHUNK_RADIX_TREE_ROOT_SIZE_LOG2 = 8;
		static constexpr uint32_t CHUNK_RADIX_TREE_ROOT_SIZE = 1UI32 << CHUNK_RADIX_TREE_ROOT_SIZE_LOG2;
		static constexpr uint32_t CHUNK_RADIX_TREE_ROOT_SIZE_MASK = CHUNK_RADIX_TREE_ROOT_SIZE - 1;
		static uint32_t chunk_radix_tree_leaf_size;
		static uint32_t chunk_radix_tree_branch_size;
		static uint32_t chunk_radix_tree_leaf_mask;
		static uint32_t chunk_radix_tree_branch_mask;
		static uint8_t chunk_radix_tree_branch_size_log2;
		static uint8_t chunk_radix_tree_leaf_size_log2;
#endif
		static uint8_t page_size_log2;
		static uint8_t chunk_size_log2;

		MPMALLOC_INLINE_ALWAYS static void init()
		{
			large_page_size = GetLargePageMinimum();
			SYSTEM_INFO info;
			GetSystemInfo(&info);
			processor_count = info.dwNumberOfProcessors;
			page_size = info.dwPageSize;
			vas_granularity = info.dwAllocationGranularity;
			MPMALLOC_INVARIANT(page_size <= params::SMALL_SIZE_CLASSES[params::SIZE_CLASS_COUNT - 1]);
			chunk_size = info.dwPageSize * std::hardware_constructive_interference_size * 8;
			chunk_size_mask = chunk_size - 1;
			MPMALLOC_INVARIANT(params::chunk_size >= (32 * 4096));
			page_size_log2 = floor_log2(page_size);
			chunk_size_log2 = floor_log2(chunk_size);
			min_address = info.lpMinimumApplicationAddress;
			max_address = info.lpMaximumApplicationAddress;
			min_chunk = (void*)MPMALLOC_ALIGN_ROUND((size_t)info.lpMinimumApplicationAddress, chunk_size);
#ifdef MPMALLOC_64BIT
			chunk_radix_tree_leaf_size_log2 = chunk_size_log2 - 3;
			chunk_radix_tree_branch_size_log2 = 64 - CHUNK_RADIX_TREE_ROOT_SIZE_LOG2 - chunk_radix_tree_leaf_size_log2 - chunk_size_log2;
			chunk_radix_tree_branch_size = 1UI32 << chunk_radix_tree_branch_size_log2;
			chunk_radix_tree_leaf_size = 1UI32 << chunk_radix_tree_leaf_size_log2;
			chunk_radix_tree_branch_mask = chunk_radix_tree_branch_size - 1;
			chunk_radix_tree_leaf_mask = chunk_radix_tree_leaf_size - 1;
#endif
		}
	}

	MPMALLOC_INLINE_ALWAYS static size_t chunk_size_of(size_t size)
	{
		size *= params::BLOCK_ALLOCATOR_MAX_CAPACITY;
		if (size > params::chunk_size)
			size = params::chunk_size;
		size = round_pow2(size);
		return size;
	}

#ifdef MPMALLOC_WINDOWS
	namespace os
	{
		using thread_id = DWORD;

		static const HANDLE process_handle = GetCurrentProcess();
		static decltype(VirtualAlloc2)* aligned_allocate;

		static void init()
		{
			HMODULE m = GetModuleHandle(TEXT("KernelBase.DLL"));
			MPMALLOC_INVARIANT(m != NULL);
			aligned_allocate = (decltype(VirtualAlloc2)*)GetProcAddress(m, "VirtualAlloc2");
		}

		static void* allocate(size_t size)
		{
			return VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		}

		static void* allocate_chunk_aligned(size_t size)
		{
			MEM_ADDRESS_REQUIREMENTS req = {};
			req.Alignment = params::chunk_size;
			req.HighestEndingAddress = params::max_address;
			req.LowestStartingAddress = params::min_chunk;
			MEM_EXTENDED_PARAMETER param = {};
			param.Type = MemExtendedParameterAddressRequirements;
			param.Pointer = &req;
			return aligned_allocate(process_handle, nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, &param, 1);
		}

		static void deallocate(void* ptr, size_t size)
		{
			MPMALLOC_INVARIANT(ptr != nullptr);
			bool result = VirtualFree(ptr, 0, MEM_RELEASE);
			MPMALLOC_INVARIANT(result);
		}

		static void purge(void* ptr, size_t size)
		{
			MPMALLOC_INVARIANT(ptr != nullptr);
			(void)DiscardVirtualMemory(ptr, size);
		}

		static void protect_readwrite(void* ptr, size_t size)
		{
			MPMALLOC_INVARIANT(ptr != nullptr);
			DWORD old;
			(void)VirtualProtect(ptr, size, PAGE_READWRITE, &old);
		}

		static void protect_readonly(void* ptr, size_t size)
		{
			MPMALLOC_INVARIANT(ptr != nullptr);
			DWORD old;
			(void)VirtualProtect(ptr, size, PAGE_READONLY, &old);
		}

		static void protect_noaccess(void* ptr, size_t size)
		{
			MPMALLOC_INVARIANT(ptr != nullptr);
			DWORD old;
			(void)VirtualProtect(ptr, size, PAGE_READWRITE, &old);
		}

		MPMALLOC_INLINE_ALWAYS static uint_fast32_t this_thread_id()
		{
			return GetCurrentThreadId();
		}

		MPMALLOC_INLINE_ALWAYS static uint_fast32_t this_processor_index()
		{
			PROCESSOR_NUMBER pn;
			GetCurrentProcessorNumberEx(&pn);
			return (pn.Group << 6) | pn.Number;
		}

		MPMALLOC_INLINE_ALWAYS static void this_thread_yield()
		{
			(void)SwitchToThread();
		}

		MPMALLOC_INLINE_ALWAYS static bool does_thread_exist(thread_id id)
		{
			HANDLE thread = OpenThread(SYNCHRONIZE, false, id);
			MPMALLOC_UNLIKELY_IF(thread == nullptr)
				return false;
			DWORD code = WaitForSingleObject(thread, 0);
			MPMALLOC_INVARIANT(code != WAIT_FAILED);
			return code == WAIT_TIMEOUT;
		}
	}
#endif

	namespace backend
	{
		namespace callbacks
		{
			static void (*init)() = os::init;
			static void (*finalize)() = nullptr;
			static void* (*allocate)(size_t size) = os::allocate;
			static void* (*allocate_chunk_aligned)(size_t size) = os::allocate_chunk_aligned;
			static void (*deallocate)(void* ptr, size_t size) = os::deallocate;
			static void (*purge)(void* ptr, size_t size) = os::purge;
			static void (*protect_readwrite)(void* ptr, size_t size) = os::protect_readwrite;
			static void (*protect_readonly)(void* ptr, size_t size) = os::protect_readonly;
			static void (*protect_noaccess)(void* ptr, size_t size) = os::protect_noaccess;
		}

		MPMALLOC_INLINE_ALWAYS static void init()
		{
			MPMALLOC_LIKELY_IF(callbacks::init != nullptr)
				callbacks::init();
		}

		MPMALLOC_INLINE_ALWAYS static void finalize()
		{
			MPMALLOC_LIKELY_IF(callbacks::finalize != nullptr)
				callbacks::finalize();
		}

		MPMALLOC_INLINE_ALWAYS static void* allocate(size_t size)
		{
			MPMALLOC_LIKELY_IF(callbacks::allocate != nullptr)
				return callbacks::allocate(size);
			return nullptr;
		}

		MPMALLOC_INLINE_ALWAYS static void* allocate_chunk_aligned(size_t size)
		{
			MPMALLOC_LIKELY_IF(callbacks::allocate_chunk_aligned != nullptr)
				return callbacks::allocate_chunk_aligned(size);
			return nullptr;
		}

		MPMALLOC_INLINE_ALWAYS static void deallocate(void* ptr, size_t size)
		{
			MPMALLOC_LIKELY_IF(callbacks::deallocate != nullptr)
				callbacks::deallocate(ptr, size);
		}

		MPMALLOC_INLINE_ALWAYS static void purge(void* ptr, size_t size)
		{
			MPMALLOC_LIKELY_IF(callbacks::purge != nullptr)
				callbacks::purge(ptr, size);
		}

		MPMALLOC_INLINE_ALWAYS static void protect_readwrite(void* ptr, size_t size)
		{
			MPMALLOC_LIKELY_IF(callbacks::protect_readwrite != nullptr)
				callbacks::protect_readwrite(ptr, size);
		}

		MPMALLOC_INLINE_ALWAYS static void protect_readonly(void* ptr, size_t size)
		{
			MPMALLOC_LIKELY_IF(callbacks::protect_readonly != nullptr)
				callbacks::protect_readonly(ptr, size);
		}

		MPMALLOC_INLINE_ALWAYS static void protect_noaccess(void* ptr, size_t size)
		{
			MPMALLOC_LIKELY_IF(callbacks::protect_noaccess != nullptr)
				callbacks::protect_noaccess(ptr, size);
		}
	}

	namespace time
	{
#ifdef MPMALLOC_WINDOWS
		using ticks_type = uint64_t;
#endif
		MPMALLOC_INLINE_ALWAYS static uint_fast64_t now()
		{
#ifdef MPMALLOC_WINDOWS
			LARGE_INTEGER r;
			(void)QueryPerformanceCounter(&r);
			return r.QuadPart;
#endif
		}
		MPMALLOC_INLINE_ALWAYS static uint_fast64_t ticks_to_ns(uint_fast64_t ticks)
		{
#ifdef MPMALLOC_WINDOWS
			LARGE_INTEGER r;
			(void)QueryPerformanceFrequency(&r);
			ticks *= 1000000000;
			ticks /= r.QuadPart;
#endif
			return ticks;
		}
	}

	template <typename T>
	struct MPMALLOC_SHARED_ATTR cache_aligned
	{
		T value;
	};

	struct free_list_node
	{
		free_list_node* next;
	};

	struct free_list
	{
		free_list_node* head;

		MPMALLOC_INLINE_ALWAYS void push(void* ptr)
		{
			free_list_node* nh = (free_list_node*)ptr;
			nh->next = head;
			head = nh;
		}

		MPMALLOC_INLINE_ALWAYS void* pop()
		{
			void* r = head;
			MPMALLOC_LIKELY_IF(r != nullptr)
				head = head->next;
			return r;
		}

		MPMALLOC_INLINE_ALWAYS void* peek()
		{
			return head;
		}
	};

	struct recovered_list
	{
		std::atomic<free_list_node*> head;

		MPMALLOC_INLINE_ALWAYS void push(void* ptr)
		{
			free_list_node* new_head = (free_list_node*)ptr;
			for (;; MPMALLOC_SPIN_WAIT)
			{
				free_list_node* prior = head.load(std::memory_order_acquire);
				new_head->next = prior;
				MPMALLOC_LIKELY_IF(head.compare_exchange_weak(prior, new_head, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
		}

		MPMALLOC_INLINE_ALWAYS void* peek()
		{
			return head.load(std::memory_order_acquire);
		}

		MPMALLOC_INLINE_ALWAYS free_list_node* pop_all()
		{
			return head.exchange(nullptr, std::memory_order_acquire);
		}
	};

	struct shared_chunk_list
	{
		std::atomic<size_t> head;

		MPMALLOC_INLINE_ALWAYS void push(void* ptr)
		{
			size_t counter_mask = params::chunk_size - 1;
			size_t pointer_mask = ~counter_mask;

			free_list_node* new_head = (free_list_node*)ptr;

			for (;; MPMALLOC_SPIN_WAIT)
			{
				size_t prior = head.load(std::memory_order_acquire);
				free_list_node* prior_head = (free_list_node*)(prior & pointer_mask);
				new_head->next = prior_head;
				size_t counter = prior;
				++counter;
				counter &= counter_mask;
				size_t desired = (size_t)new_head;
				desired |= counter;
				MPMALLOC_LIKELY_IF(head.compare_exchange_weak(prior, desired, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
		}

		MPMALLOC_INLINE_ALWAYS void* pop()
		{
			size_t counter_mask = params::chunk_size - 1;
			size_t pointer_mask = ~counter_mask;
			for (;; MPMALLOC_SPIN_WAIT)
			{
				size_t prior = head.load(std::memory_order_acquire);
				free_list_node* prior_head = (free_list_node*)(prior & pointer_mask);
				MPMALLOC_UNLIKELY_IF(prior_head == nullptr)
					return nullptr;
				free_list_node* new_head = prior_head->next;
				size_t counter = prior;
				++counter;
				counter &= counter_mask;
				size_t desired = (size_t)new_head;
				desired |= counter;
				MPMALLOC_LIKELY_IF(head.compare_exchange_weak(prior, desired, std::memory_order_acquire, std::memory_order_relaxed))
					return prior_head;
			}
		}

		MPMALLOC_INLINE_ALWAYS void* peek()
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

		MPMALLOC_INLINE_ALWAYS void push(void* new_head)
		{
			head_type prior, desired;
			desired.head = (free_list_node*)new_head;
			for (;; MPMALLOC_SPIN_WAIT)
			{
				prior = head.load(std::memory_order_acquire);
				desired.head->next = prior.head;
				desired.generation = prior.generation + 1;
				MPMALLOC_LIKELY_IF(head.compare_exchange_weak(prior, desired, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
		}

		MPMALLOC_INLINE_ALWAYS void* pop()
		{
			head_type prior, desired;
			for (;; MPMALLOC_SPIN_WAIT)
			{
				prior = head.load(std::memory_order_acquire);
				MPMALLOC_UNLIKELY_IF(prior.head == nullptr)
					break;
				desired.head = prior.head->next;
				desired.generation = prior.generation + 1;
				MPMALLOC_LIKELY_IF(head.compare_exchange_weak(prior, desired, std::memory_order_acquire, std::memory_order_relaxed))
					break;
			}
			return prior.head;
		}
	};

#ifdef MPMALLOC_64BIT
	template <typename T>
	struct chunk_radix_tree
	{
		using tagged_ptr = size_t;

		static constexpr uint8_t REFC_COUNT_LOG2 = 8;
		static constexpr uint32_t REFC_COUNT = 1UI32 << REFC_COUNT_LOG2;
		static constexpr uint32_t REFC_MASK = REFC_COUNT - 1;

		std::atomic<std::atomic<T*>*> roots[params::CHUNK_RADIX_TREE_ROOT_SIZE];
		std::atomic<uint32_t> leaf_ref_counts[REFC_COUNT];

		MPMALLOC_INLINE_ALWAYS static void break_key(size_t key, uint_fast32_t& root_index, uint_fast32_t& branch_index, uint_fast32_t& leaf_index)
		{
			key >>= params::chunk_size_log2;
			leaf_index = key & params::chunk_radix_tree_leaf_mask;
			key >>= params::chunk_radix_tree_leaf_size_log2;
			branch_index = key & params::chunk_radix_tree_branch_mask;
			key >>= params::chunk_radix_tree_branch_size_log2;
			root_index = (uint_fast32_t)key;
		}

		MPMALLOC_INLINE_ALWAYS T* find_or_insert(size_t key)
		{
			uint_fast32_t root_index, branch_index, leaf_index;
			break_key(key, root_index, branch_index, leaf_index);
			std::atomic<std::atomic<T*>*>& root = roots[root_index];
			std::atomic<T*>* branch = root.load(std::memory_order_acquire);
			MPMALLOC_UNLIKELY_IF(branch == nullptr)
			{
				std::atomic<T*>* desired = (std::atomic<T*>*)large_cache::allocate(params::chunk_radix_tree_branch_size * sizeof(std::atomic<T*>));
				MPMALLOC_UNLIKELY_IF (root.compare_exchange_strong(branch, desired, std::memory_order_acquire, std::memory_order_relaxed))
				{
					branch = desired;
				}
				else
				{
					large_cache::deallocate(branch, params::chunk_radix_tree_branch_size * sizeof(std::atomic<T*>));
					branch = root.load(std::memory_order_acquire);
				}
			}
			std::atomic<T*>& leaf_ptr = branch[branch_index];
			T* leaf = leaf_ptr.load(std::memory_order_acquire);
			MPMALLOC_UNLIKELY_IF(leaf == nullptr)
			{
				T* desired = (T*)large_cache::allocate(params::chunk_radix_tree_leaf_size * sizeof(T));
				MPMALLOC_UNLIKELY_IF(leaf_ptr.compare_exchange_strong(leaf, desired, std::memory_order_acquire, std::memory_order_relaxed))
				{
					leaf = desired;
				}
				else
				{
					large_cache::deallocate(desired, params::chunk_radix_tree_leaf_size * sizeof(T));
					leaf = leaf_ptr.load(std::memory_order_acquire);
				}
			}
			return &leaf[leaf_index];
		}

		MPMALLOC_INLINE_ALWAYS T* find(size_t key)
		{
			uint_fast32_t root_index, branch_index, leaf_index;
			break_key(key, root_index, branch_index, leaf_index);
			std::atomic<T*>* branch = roots[root_index].load(std::memory_order_acquire);
			MPMALLOC_UNLIKELY_IF(branch == nullptr)
				return nullptr;
			T* leaf = branch[branch_index].load(std::memory_order_acquire);
			MPMALLOC_UNLIKELY_IF(leaf == nullptr)
				return nullptr;
			return &leaf[leaf_index];
		}

		template <typename F>
		MPMALLOC_INLINE_ALWAYS void erase(size_t key, F&& destructor)
		{
			uint_fast32_t root_index, branch_index, leaf_index;
			break_key(key, root_index, branch_index, leaf_index);
			std::atomic<T*>* branch = roots[root_index].load(std::memory_order_acquire);
			MPMALLOC_INVARIANT(branch != nullptr);
			T* leaf = branch[branch_index].load(std::memory_order_acquire);
			MPMALLOC_INVARIANT(leaf != nullptr);
			destructor(leaf[leaf_index]);
		}

		template <typename F>
		MPMALLOC_INLINE_ALWAYS void for_each(F&& function)
		{
		}
	};
#endif

	namespace statistics
	{
		static std::atomic<size_t> used_memory;
		static std::atomic<size_t> total_memory;
		static std::atomic<size_t> used_vas;
		static std::atomic<size_t> total_vas;

		size_t used_physical_memory()
		{
			return used_memory.load(std::memory_order_acquire);
		}

		size_t total_physical_memory()
		{
			return total_memory.load(std::memory_order_acquire);
		}

		size_t used_address_space()
		{
			return used_vas.load(std::memory_order_acquire);
		}

		size_t total_address_space()
		{
			return total_vas.load(std::memory_order_acquire);
		}
	}

	namespace large_cache
	{
		size_t block_size_of(size_t size)
		{
			size_t r = MPMALLOC_ALIGN_ROUND(size, params::chunk_size);
			MPMALLOC_UNLIKELY_IF(r < params::chunk_size)
				r = 0;
			return r;
		}

#ifndef MPMALLOC_64BIT
		static shared_chunk_list* bins;

		void init()
		{
			size_t buffer_size = sizeof(shared_chunk_list) << (32 - params::chunk_size_log2);
			bins = (shared_chunk_list*)backend::allocate_chunk_aligned(buffer_size);
		}

		void finalize()
		{
			size_t buffer_size = sizeof(shared_chunk_list) << (32 - params::chunk_size_log2);
			backend::deallocate(bins, buffer_size);
		}

		void* try_allocate(size_t size)
		{
			size >>= params::chunk_size_log2;
			--size;
			return bins[size].pop();
		}

		void* allocate(size_t size)
		{
			void* r = try_allocate(size);
			MPMALLOC_UNLIKELY_IF(r == nullptr)
				r = backend::allocate_chunk_aligned(MPMALLOC_ALIGN_ROUND(size, params::chunk_size));
			return r;
		}

		void deallocate(void* ptr, size_t size)
		{
			size >>= params::chunk_size_log2;
			--size;
			bins[size].push(ptr);
		}

		size_t trim()
		{
			return 0;
		}

		size_t purge()
		{
			return 0;
		}
#else
		MPMALLOC_SHARED_ATTR static shared_chunk_list single_chunk_bin;

		static constexpr uint8_t SHARD_COUNT_LOG2 = 8;
		static constexpr size_t SHARD_MASK = 255;
		static chunk_radix_tree<shared_chunk_list> lookup;

		void init()
		{
		}

		void finalize()
		{
		}

		void* try_allocate(size_t size)
		{
			size >>= params::chunk_size_log2;
			--size;
			MPMALLOC_LIKELY_IF(size == 0)
				return single_chunk_bin.pop();
			shared_chunk_list* bin = lookup.find(size);
			MPMALLOC_UNLIKELY_IF(bin == nullptr)
				return nullptr;
			return bin->pop();
		}

		void* allocate(size_t size)
		{
			void* r = try_allocate(size);
			MPMALLOC_UNLIKELY_IF(r == nullptr)
				r = backend::allocate_chunk_aligned(size);
			return r;
		}

		void deallocate(void* ptr, size_t size)
		{
			size >>= params::chunk_size_log2;
			--size;
			MPMALLOC_LIKELY_IF(size == 0)
				return single_chunk_bin.push(ptr);
			lookup.find_or_insert(size)->push(ptr);
		}

		size_t trim()
		{
			size_t r = 0;
			return r;
		}

		size_t purge()
		{
			size_t r = 0;
			return r;
		}
#endif
	}

	namespace shared_cache
	{
		struct MPMALLOC_SHARED_ATTR shared_block_allocator
		{
			shared_block_allocator* next;
			shared_block_allocator_recover_list* recovered;
			uint8_t* buffer;
			uint32_t capacity;
			uint8_t block_size_log2;
			std::atomic<uint32_t> begin_free_mask;
			std::atomic<uint32_t> free_count;
			std::atomic_bool unlinked;
			MPMALLOC_SHARED_ATTR std::atomic<params::mask_type> free_map[params::BLOCK_ALLOCATOR_MASK_COUNT];

			MPMALLOC_INLINE_ALWAYS void init(uint_fast8_t block_size_log2, shared_block_allocator_recover_list* recovered, uint8_t* buffer)
			{
				this->next = nullptr;
				this->recovered = recovered;
				this->buffer = buffer;
				capacity = (uint32_t)(params::chunk_size >> block_size_log2);
				non_atomic_store(free_count, capacity);
				this->block_size_log2 = block_size_log2;
				non_atomic_store(unlinked, false);
				(void)memset(free_map, 0, sizeof(free_map));
				uint_fast32_t mask_count = capacity >> params::BLOCK_MASK_BIT_SIZE_LOG2;
				uint_fast32_t bit_count = capacity & params::BLOCK_MASK_MOD_MASK;
				MPMALLOC_LIKELY_IF(mask_count != 0)
					(void)memset(free_map, 0xff, mask_count * sizeof(params::mask_type));
				MPMALLOC_LIKELY_IF(bit_count != 0)
					non_atomic_store(free_map[mask_count], ((params::mask_type)1 << bit_count) - (params::mask_type)1);
			}

			MPMALLOC_INLINE_ALWAYS uint_fast32_t index_of(void* ptr)
			{
				return ((uint_fast32_t)((uint8_t*)ptr - buffer)) >> block_size_log2;
			}

			MPMALLOC_INLINE_ALWAYS void* allocate()
			{
				while (true)
				{
					for (uint_fast32_t i = 0; i != params::BLOCK_ALLOCATOR_MASK_COUNT; ++i)
					{
						MPMALLOC_UNLIKELY_IF(free_count.load(std::memory_order_acquire) == 0)
							return nullptr;

						for (;; MPMALLOC_SPIN_WAIT)
						{
							params::mask_type prior = free_map[i].load(std::memory_order_acquire);
							MPMALLOC_UNLIKELY_IF(prior == 0)
								break;
							uint_fast8_t j = find_first_set(prior);
							params::mask_type desired = prior;
							bit_reset(desired, j);
							MPMALLOC_LIKELY_IF(free_map[i].compare_exchange_weak(prior, desired, std::memory_order_acquire, std::memory_order_relaxed))
							{
								(void)free_count.fetch_sub(1, std::memory_order_release);
								return buffer + (((i << params::BLOCK_MASK_BIT_SIZE_LOG2) | j) << block_size_log2);
							}
						}
					}
				}
			}

			MPMALLOC_INLINE_NEVER void recover()
			{
				bool expected = true;
				MPMALLOC_LIKELY_IF(unlinked.compare_exchange_strong(expected, false, std::memory_order_acquire, std::memory_order_relaxed))
					recovered->push(this);
			}

			MPMALLOC_INLINE_ALWAYS void deallocate(void* ptr)
			{
				uint_fast32_t index = index_of(ptr);
				uint_fast32_t mask_index = index >> params::BLOCK_MASK_BIT_SIZE_LOG2;
				uint_fast8_t bit_index = index & params::BLOCK_MASK_MOD_MASK;
				(void)free_map[mask_index].fetch_or((params::mask_type)1 << bit_index, std::memory_order_release);
				(void)free_count.fetch_add(1, std::memory_order_relaxed);
				MPMALLOC_UNLIKELY_IF(unlinked.load(std::memory_order_acquire))
					recover();
			}

			MPMALLOC_INLINE_ALWAYS bool owns(void* ptr)
			{
				MPMALLOC_UNLIKELY_IF((uint8_t*)ptr < buffer)
					return false;
				MPMALLOC_UNLIKELY_IF((uint8_t*)ptr >= buffer + ((params::mask_type)params::BLOCK_ALLOCATOR_MAX_CAPACITY << block_size_log2))
					return false;
				uint_fast32_t index = index_of(ptr);
				uint_fast32_t mask_index = index >> params::BLOCK_MASK_BIT_SIZE_LOG2;
				uint_fast8_t bit_index = index & params::BLOCK_MASK_MOD_MASK;
				return bit_test(free_map[mask_index].load(std::memory_order_acquire), bit_index);
			}
		};

		struct MPMALLOC_SHARED_ATTR shared_allocator_list
		{
			std::atomic<shared_block_allocator*> head;

			MPMALLOC_INLINE_ALWAYS shared_block_allocator* peek()
			{
				return head.load(std::memory_order_acquire);
			}

			MPMALLOC_INLINE_ALWAYS void push(shared_block_allocator* new_head)
			{
				shared_block_allocator* prior;
				for (;; MPMALLOC_SPIN_WAIT)
				{
					prior = head.load(std::memory_order_acquire);
					new_head->next = prior;
					MPMALLOC_LIKELY_IF(head.compare_exchange_weak(prior, new_head, std::memory_order_release, std::memory_order_relaxed))
						break;
				}
			}

			MPMALLOC_INLINE_ALWAYS void pop_if_equal(shared_block_allocator* expected)
			{
				MPMALLOC_LIKELY_IF(head.compare_exchange_strong(expected, expected->next, std::memory_order_acquire, std::memory_order_relaxed))
					expected->unlinked.store(true, std::memory_order_release);
			}
		};

		static uint8_t size_class_count;
#ifndef MPMALLOC_64BIT
		static shared_block_allocator* lookup;
#else
		static chunk_radix_tree<shared_block_allocator> lookup;
#endif

		shared_allocator_list* bins;
		shared_block_allocator_recover_list* recovered;

		void init()
		{
			size_class_count = params::chunk_size_log2 - params::page_size_log2;
			size_t buffer_size = 0;
#ifndef MPMALLOC_64BIT
			size_t chunk_count = 1U << (32 - params::chunk_size_log2);
			buffer_size += chunk_count * sizeof(shared_block_allocator);
#endif
			buffer_size += size_class_count * sizeof(shared_allocator_list);
			buffer_size += size_class_count * sizeof(shared_block_allocator_recover_list);
			uint8_t* buffer = (uint8_t*)backend::allocate(buffer_size);
#ifndef MPMALLOC_64BIT
			lookup = (shared_block_allocator*)buffer;
			buffer += chunk_count * sizeof(shared_block_allocator);
#endif
			bins = (shared_allocator_list*)buffer;
			buffer += size_class_count * sizeof(shared_allocator_list);
			recovered = (shared_block_allocator_recover_list*)buffer;
		}

		void finalize()
		{
#ifndef MPMALLOC_64BIT
#else
#endif
		}

		static void* try_allocate_impl(uint_fast8_t sc)
		{
			shared_block_allocator* allocator;
			while (true)
			{
				shared_block_allocator* allocator = bins[sc].peek();
				MPMALLOC_UNLIKELY_IF(allocator == nullptr)
					break;
				void* r = allocator->allocate();
				MPMALLOC_LIKELY_IF(r != nullptr)
					return r;
				MPMALLOC_LIKELY_IF(allocator->free_count.load(std::memory_order_acquire) == 0)
					bins[sc].pop_if_equal(allocator);
			}
			allocator = (shared_block_allocator*)recovered[sc].pop();
			MPMALLOC_UNLIKELY_IF(allocator == nullptr)
				return nullptr;
			void* r = allocator->allocate();
			MPMALLOC_INVARIANT(r != nullptr);
			bins[sc].push(allocator);
			return r;
		}

		void* try_allocate(size_t size)
		{
			uint_fast8_t sc = floor_log2(size) - params::page_size_log2;
			return try_allocate_impl(sc);
		}

		void* allocate(size_t size)
		{
			uint_fast8_t size_log2 = floor_log2(size);
			uint_fast8_t sc = floor_log2(size) - params::page_size_log2;
			void* r = try_allocate_impl(sc);
			MPMALLOC_LIKELY_IF(r != nullptr)
				return r;
			uint8_t* buffer = (uint8_t*)large_cache::allocate(params::chunk_size);
			shared_block_allocator* allocator;
#ifndef MPMALLOC_64BIT
			allocator = &lookup[(size_t)buffer >> params::chunk_size_log2];
#else
			allocator = lookup.find_or_insert((size_t)buffer);
			MPMALLOC_INVARIANT(allocator != nullptr);
#endif
			allocator->init(size_log2, recovered + sc, buffer);
			r = allocator->allocate();
			bins[sc].push(allocator);
			return r;
		}

		void deallocate(void* ptr, size_t size)
		{
#ifndef MPMALLOC_64BIT
			lookup[(size_t)ptr >> params::chunk_size_log2].deallocate(ptr);
#else
			lookup.find_or_insert((size_t)ptr)->deallocate(ptr);
#endif
		}

		size_t block_size_of(size_t size)
		{
			return round_pow2(size);
		}

		size_t trim()
		{
			size_t r = 0;
			return r;
		}

		size_t purge()
		{
			size_t r = 0;
			return r;
		}
	}

	namespace thread_cache
	{
		struct MPMALLOC_SHARED_ATTR intrusive_block_allocator
		{
			intrusive_block_allocator* next;
			recovered_list* recovered;
			uint32_t free_count;
			uint32_t begin_free_mask;
			uint32_t block_size;
			uint32_t capacity;
			std::atomic<os::thread_id> owning_thread;
			std::atomic_bool unlinked;
			MPMALLOC_SHARED_ATTR params::mask_type free_map[params::BLOCK_ALLOCATOR_MASK_COUNT];
			MPMALLOC_SHARED_ATTR std::atomic<params::mask_type> marked_map[params::BLOCK_ALLOCATOR_MASK_COUNT];

			MPMALLOC_INLINE_ALWAYS void init(uint_fast32_t block_size, size_t chunk_size, recovered_list* recovered)
			{
				this->next = nullptr;
				this->recovered = recovered;
				capacity = (uint_fast32_t)(chunk_size / block_size);
				uint_fast32_t reserved_count = (uint_fast32_t)MPMALLOC_ALIGN_ROUND(sizeof(intrusive_block_allocator), (size_t)block_size) / block_size;
				free_count = capacity - reserved_count;
				begin_free_mask = 0;
				this->block_size = block_size;
				non_atomic_store(unlinked, false);
				(void)memset(free_map, 0, sizeof(free_map));
				(void)memset(marked_map, 0, sizeof(marked_map));
				uint_fast32_t mask_count = capacity >> params::BLOCK_MASK_BIT_SIZE_LOG2;
				uint_fast32_t bit_count = capacity & params::BLOCK_MASK_MOD_MASK;
				MPMALLOC_LIKELY_IF(mask_count != 0)
					(void)memset(free_map, 0xff, mask_count * sizeof(params::mask_type));
				MPMALLOC_LIKELY_IF(bit_count != 0)
					free_map[mask_count] = (1UI64 << bit_count) - 1UI64;
				mask_count = reserved_count >> params::BLOCK_MASK_BIT_SIZE_LOG2;
				bit_count = reserved_count & params::BLOCK_MASK_MOD_MASK;
				MPMALLOC_LIKELY_IF(mask_count != 0)
					(void)memset(free_map, 0, mask_count * sizeof(params::mask_type));
				MPMALLOC_LIKELY_IF(bit_count != 0)
					free_map[0] &= ~((1UI64 << bit_count) - 1UI64);
			}

			MPMALLOC_INLINE_NEVER uint_fast32_t reclaim()
			{
				uint_fast32_t freed_count = 0;
				for (uint_fast32_t i = 0; i != params::BLOCK_ALLOCATOR_MASK_COUNT; ++i)
				{
					MPMALLOC_LIKELY_IF(marked_map[i].load(std::memory_order_acquire) != 0)
					{
						params::mask_type mask = marked_map[i].exchange(0, std::memory_order_acquire);
						free_map[i] |= mask;
						freed_count += MPMALLOC_POPCOUNT(mask);
					}
				}
				return freed_count;
			}

			MPMALLOC_INLINE_ALWAYS uint_fast32_t index_of(void* ptr)
			{
				return ((uint_fast32_t)((uint8_t*)ptr - (uint8_t*)this)) / block_size;
			}

			MPMALLOC_INLINE_ALWAYS void* allocate()
			{
				for (uint_fast32_t mask_index = begin_free_mask; mask_index != params::BLOCK_ALLOCATOR_MASK_COUNT; ++mask_index)
				{
					MPMALLOC_LIKELY_IF(free_map[mask_index] != 0)
					{
						MPMALLOC_LIKELY_IF(begin_free_mask < mask_index)
							begin_free_mask = mask_index;
						uint_fast8_t bit_index = find_first_set(free_map[mask_index]);
						bit_reset(free_map[mask_index], bit_index);
						uint_fast32_t offset = (mask_index << params::BLOCK_MASK_BIT_SIZE_LOG2) | bit_index;
						offset *= block_size;
						--free_count;
						MPMALLOC_UNLIKELY_IF(free_count == 0)
							free_count += reclaim();
						return (uint8_t*)this + offset;
					}
				}
				MPMALLOC_UNREACHABLE;
			}

			MPMALLOC_INLINE_NEVER void final_recover(os::thread_id prior_owner)
			{
				MPMALLOC_LIKELY_IF(owning_thread.compare_exchange_strong(prior_owner, os::this_thread_id(), std::memory_order_acquire, std::memory_order_relaxed))
				{
					reclaim();
					MPMALLOC_UNLIKELY_IF(free_count == capacity)
						mpmalloc::deallocate(this, chunk_size_of(block_size));
				}
			}

			MPMALLOC_INLINE_NEVER void recover()
			{
				os::thread_id prior_owner = owning_thread.load(std::memory_order_acquire);
				MPMALLOC_UNLIKELY_IF(!os::does_thread_exist(prior_owner))
					return final_recover(prior_owner);
				bool expected = true;
				MPMALLOC_LIKELY_IF(unlinked.compare_exchange_strong(expected, false, std::memory_order_acquire, std::memory_order_relaxed))
					recovered->push(this);
			}

			MPMALLOC_INLINE_ALWAYS void deallocate(void* ptr)
			{
				++free_count;
				uint_fast32_t index = index_of(ptr);
				uint_fast32_t mask_index = index >> params::BLOCK_MASK_BIT_SIZE_LOG2;
				uint_fast32_t bit_index = index & params::BLOCK_MASK_MOD_MASK;
				MPMALLOC_UNLIKELY_IF(begin_free_mask < mask_index)
					begin_free_mask = mask_index;
				bit_set(free_map[mask_index], bit_index);
				MPMALLOC_UNLIKELY_IF(unlinked.load(std::memory_order_acquire))
					recover();
			}

			MPMALLOC_INLINE_ALWAYS void deallocate_shared(void* ptr)
			{
				uint_fast32_t index = index_of(ptr);
				uint_fast32_t mask_index = index >> params::BLOCK_MASK_BIT_SIZE_LOG2;
				uint_fast32_t bit_index = index & params::BLOCK_MASK_MOD_MASK;
				(void)marked_map[mask_index].fetch_or(1UI64 << bit_index, std::memory_order_release);
				MPMALLOC_UNLIKELY_IF(unlinked.load(std::memory_order_acquire))
					recover();
			}

			MPMALLOC_INLINE_ALWAYS bool owns(void* ptr)
			{
				MPMALLOC_UNLIKELY_IF((uint8_t*)ptr < (uint8_t*)this)
					return false;
				MPMALLOC_UNLIKELY_IF((uint8_t*)ptr >= (uint8_t*)this + (size_t)params::BLOCK_ALLOCATOR_MAX_CAPACITY * block_size)
					return false;
				uint_fast32_t index = index_of(ptr);
				uint_fast32_t mask_index = index >> params::BLOCK_MASK_BIT_SIZE_LOG2;
				uint_fast32_t bit_index = index & params::BLOCK_MASK_MOD_MASK;
				return bit_test(free_map[mask_index], bit_index);
			}

			MPMALLOC_INLINE_ALWAYS static intrusive_block_allocator* allocator_of(void* ptr, size_t chunk_size)
			{
				size_t mask = (size_t)ptr;
				mask = MPMALLOC_ALIGN_FLOOR(mask, chunk_size);
				return (intrusive_block_allocator*)mask;
			}
		};

		struct thread_cache_state
		{
			free_list small_bins[params::SIZE_CLASS_COUNT];
			cache_aligned<recovered_list>small_recovered[params::SIZE_CLASS_COUNT];
			free_list* large_bins;
			cache_aligned<recovered_list>* large_recovered;
		};

		thread_local static thread_cache_state here;

		uint_fast8_t size_class_of(size_t size)
		{
			for (uint_fast8_t i = 0; i != params::SIZE_CLASS_COUNT; ++i)
				MPMALLOC_UNLIKELY_IF(params::SMALL_SIZE_CLASSES[i] >= size)
					return i;
			MPMALLOC_UNREACHABLE;
		}

		size_t block_size_of_unsafe(size_t size)
		{
			return params::SMALL_SIZE_CLASSES[size_class_of(size)];
		}

		size_t block_size_of(size_t size)
		{
			MPMALLOC_UNLIKELY_IF(size == 0 || size > params::page_size)
				return 0;
			return block_size_of_unsafe(size);
		}

		MPMALLOC_INLINE_NEVER static void* allocate_fallback(uint_fast8_t sc)
		{
			cache_aligned<recovered_list>& e = here.small_recovered[sc];
			intrusive_block_allocator* head = (intrusive_block_allocator*)e.value.pop_all();
			MPMALLOC_UNLIKELY_IF(head == nullptr)
				return nullptr;
			MPMALLOC_INVARIANT(head->free_count != 0);
			void* r = head->allocate();
			MPMALLOC_UNLIKELY_IF(head->free_count == 0)
			{
				head->unlinked.store(true, std::memory_order_release);
				head = (intrusive_block_allocator*)head->next;
			}
			MPMALLOC_INVARIANT(here.small_bins[sc].head == nullptr);
			here.small_bins[sc].head = (free_list_node*)head;
			return r;
		}

		void* try_allocate_impl(uint_fast8_t sc)
		{
			free_list& bin = here.small_bins[sc];
			intrusive_block_allocator* head = (intrusive_block_allocator*)bin.peek();
			MPMALLOC_LIKELY_IF(head == nullptr)
				return allocate_fallback(sc);
			MPMALLOC_INVARIANT(head->free_count != 0);
			void* r = head->allocate();
			MPMALLOC_UNLIKELY_IF(head->free_count == 0)
			{
				(void)bin.pop();
				head->unlinked.store(true, std::memory_order_release);
			}
			return r;
		}

		void* try_allocate(size_t size)
		{
			uint_fast8_t sc = size_class_of(size);
			return try_allocate_impl(sc);
		}

		void* allocate(size_t size)
		{
			MPMALLOC_UNLIKELY_IF(size == 0)
				return nullptr;
			uint_fast8_t sc = size_class_of(size);
			void* r = try_allocate_impl(sc);
			MPMALLOC_UNLIKELY_IF(r != nullptr)
				return r;
			size = block_size_of_unsafe(size);
			size_t chunk_size = chunk_size_of(size);
			intrusive_block_allocator* allocator = (intrusive_block_allocator*)mpmalloc::allocate(chunk_size);
			MPMALLOC_UNLIKELY_IF(allocator == nullptr)
				return nullptr;
			allocator->init((uint_fast32_t)size, chunk_size, &(here.small_recovered[sc].value));
			non_atomic_store(allocator->owning_thread, os::this_thread_id());
			MPMALLOC_INVARIANT(allocator->free_count != 0);
			r = allocator->allocate();
			MPMALLOC_INVARIANT(allocator->free_count != 0);
			here.small_bins[sc].push(allocator);
			return r;
		}

		void deallocate(void* ptr, size_t size)
		{
#ifndef MPMALLOC_NO_ZERO_SIZE_CHECK
			size |= (size == 0);
#endif
			uint_fast8_t sc = size_class_of(size);
			recovered_list* expected_recovered_list = &(here.small_recovered[sc].value);
			intrusive_block_allocator* allocator = intrusive_block_allocator::allocator_of(ptr, chunk_size_of(size));
			MPMALLOC_LIKELY_IF(allocator->recovered == expected_recovered_list)
				allocator->deallocate(ptr);
			else
				allocator->deallocate_shared(ptr);
		}

		void init()
		{
		}

		void finalize()
		{
		}

		size_t trim()
		{
			size_t r = 0;
			return r;
		}

		size_t purge()
		{
			size_t r = 0;
			return r;
		}
	}

	void init(const init_options* options)
	{
		MPMALLOC_LIKELY_IF(options != nullptr && options->backend != nullptr)
		{
			backend::callbacks::init = options->backend->init;
			backend::callbacks::finalize = options->backend->finalize;
			backend::callbacks::allocate = options->backend->allocate;
			backend::callbacks::allocate_chunk_aligned = options->backend->allocate_chunk_aligned;
			backend::callbacks::deallocate = options->backend->deallocate;
			backend::callbacks::purge = options->backend->purge;
			backend::callbacks::protect_readwrite = options->backend->protect_readwrite;
			backend::callbacks::protect_readonly = options->backend->protect_readonly;
			backend::callbacks::protect_noaccess = options->backend->protect_noaccess;
		}

		params::init();
		backend::init();
		large_cache::init();
		shared_cache::init();
	}

	void finalize()
	{
		shared_cache::finalize();
		large_cache::finalize();
		backend::init();
	}

	void init_thread()
	{
		thread_cache::init();
	}

	void finalize_thread()
	{
		thread_cache::finalize();
	}

	void* allocate(size_t size)
	{
		MPMALLOC_UNLIKELY_IF(size == 0)
			return nullptr;
		void* r;
		MPMALLOC_LIKELY_IF(size <= params::page_size)
			r = thread_cache::allocate(size);
		else MPMALLOC_LIKELY_IF(size < params::chunk_size)
			r = shared_cache::allocate(size);
		else
			r = large_cache::allocate(size);
#if defined(MPMALLOC_DEBUG) && !defined(MPMALLOC_NO_JUNK)
		(void)memset(r, MPMALLOC_JUNK_VALUE, size);
#endif
		return r;
	}

	bool try_expand(void* ptr, size_t old_size, size_t new_size)
	{
		size_t rounded_old_size = block_size_of(old_size);
		return rounded_old_size >= new_size;
	}

	void* reallocate(void* ptr, size_t old_size, size_t new_size)
	{
		MPMALLOC_INVARIANT(ptr != nullptr || old_size == 0);
		MPMALLOC_UNLIKELY_IF(try_expand(ptr, old_size, new_size))
			return ptr;
		void* r = allocate(new_size);
		MPMALLOC_LIKELY_IF(r == nullptr)
			return r;
		(void)memcpy(r, ptr, old_size);
		deallocate(ptr, old_size);
		return r;
	}

	void deallocate(void* ptr, size_t size)
	{
		MPMALLOC_UNLIKELY_IF(ptr == nullptr)
			return;
		MPMALLOC_LIKELY_IF(size <= params::page_size)
			return thread_cache::deallocate(ptr, size);
		else MPMALLOC_LIKELY_IF(size < params::chunk_size)
			return shared_cache::deallocate(ptr, size);
		else
			return large_cache::deallocate(ptr, size);
	}

	size_t block_size_of(size_t size)
	{
		MPMALLOC_LIKELY_IF(size <= params::page_size)
			return thread_cache::block_size_of(size);
		else MPMALLOC_LIKELY_IF(size < params::chunk_size)
			return shared_cache::block_size_of(size);
		else
			return large_cache::block_size_of(size);
	}

	size_t trim()
	{
		size_t r = 0;
		r += thread_cache::trim();
		r += shared_cache::trim();
		r += large_cache::trim();
		return r;
	}

	size_t purge()
	{
		size_t r = 0;
		r += thread_cache::purge();
		r += shared_cache::purge();
		r += large_cache::purge();
		return r;
	}

	backend_options default_backend()
	{
		backend_options r;
		r.init = os::init;
		r.finalize = nullptr;
		r.allocate = os::allocate;
		r.allocate_chunk_aligned = os::allocate_chunk_aligned;
		r.deallocate = os::deallocate;
		r.purge = os::purge;
		r.protect_readwrite = os::protect_readwrite;
		r.protect_readonly = os::protect_readonly;
		r.protect_noaccess = os::protect_noaccess;
		return r;
	}

	backend_options current_backend()
	{
		backend_options r;
		r.init =backend::init;
		r.finalize = backend::finalize;
		r.allocate = backend::allocate;
		r.allocate_chunk_aligned = backend::allocate_chunk_aligned;
		r.deallocate = backend::deallocate;
		r.purge = backend::purge;
		r.protect_readwrite = backend::protect_readwrite;
		r.protect_readonly = backend::protect_readonly;
		r.protect_noaccess = backend::protect_noaccess;
		return r;
	}

	platform_information platform_info()
	{
		platform_information r;
		r.processor_count = params::processor_count;
		r.cache_line_size = std::hardware_constructive_interference_size;
		r.page_size = params::page_size;
		r.large_page_size = params::large_page_size;
		r.chunk_size = params::chunk_size;
		r.address_space_granularity = params::vas_granularity;
		r.min_address = params::min_chunk;
		r.max_address = params::max_address;
		return r;
	}
}
#endif