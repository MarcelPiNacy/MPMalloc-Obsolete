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
#include <cstddef>

#ifndef MPMALLOC_CALL
#define MPMALLOC_CALL
#endif

#ifndef MPMALLOC_ATTR
#define MPMALLOC_ATTR
#endif

#ifndef MPMALLOC_PTR
#define MPMALLOC_PTR
#endif

#ifndef MPMALLOC_SPIN_THRESHOLD
#define MPMALLOC_SPIN_THRESHOLD 16
#endif

#ifndef MPMALLOC_MAX_LOAD_FACTOR_NUMERATOR
#define MPMALLOC_MAX_LOAD_FACTOR_NUMERATOR 15
#endif

#ifndef MPMALLOC_MAX_LOAD_FACTOR_DENOMINATOR
#define MPMALLOC_MAX_LOAD_FACTOR_DENOMINATOR 16
#endif



namespace mpmalloc
{
	namespace fn_ptr
	{
		using init = void(MPMALLOC_PTR*)();
		using finalize = void(MPMALLOC_PTR*)();
		using allocate = void* (MPMALLOC_PTR*)(size_t);
		using allocate_chunk_aligned = void* (MPMALLOC_PTR*)(size_t);
		using try_expand = bool (MPMALLOC_PTR*)(void*, size_t, size_t);
		using reallocate = void* (MPMALLOC_PTR*)(void*, size_t, size_t);
		using deallocate = void (MPMALLOC_PTR*)(void*, size_t);
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

	MPMALLOC_ATTR void MPMALLOC_CALL init(const init_options* options = nullptr);
	MPMALLOC_ATTR void MPMALLOC_CALL finalize();
	MPMALLOC_ATTR void MPMALLOC_CALL init_thread();
	MPMALLOC_ATTR void MPMALLOC_CALL finalize_thread();

	[[nodiscard]] MPMALLOC_ATTR void* MPMALLOC_CALL allocate(size_t size);
	MPMALLOC_ATTR bool MPMALLOC_CALL try_expand(void* ptr, size_t old_size, size_t new_size);
	[[nodiscard]] MPMALLOC_ATTR void* MPMALLOC_CALL reallocate(void* ptr, size_t old_size, size_t new_size);
	MPMALLOC_ATTR void MPMALLOC_CALL deallocate(void* ptr, size_t size);
	MPMALLOC_ATTR size_t MPMALLOC_CALL block_size_of(size_t size);
	MPMALLOC_ATTR size_t MPMALLOC_CALL trim();
	MPMALLOC_ATTR size_t MPMALLOC_CALL purge();

	MPMALLOC_ATTR backend_options MPMALLOC_CALL default_backend();
	MPMALLOC_ATTR backend_options MPMALLOC_CALL current_backend();
	MPMALLOC_ATTR platform_information MPMALLOC_CALL platform_info();

	namespace statistics
	{
		MPMALLOC_ATTR size_t MPMALLOC_CALL used_physical_memory();
		MPMALLOC_ATTR size_t MPMALLOC_CALL total_physical_memory();
		MPMALLOC_ATTR size_t MPMALLOC_CALL used_address_space();
		MPMALLOC_ATTR size_t MPMALLOC_CALL total_address_space();
	}

	namespace large_cache
	{
		[[nodiscard]] MPMALLOC_ATTR void* MPMALLOC_CALL try_allocate(size_t size);
		[[nodiscard]] MPMALLOC_ATTR void* MPMALLOC_CALL allocate(size_t size);
		MPMALLOC_ATTR void MPMALLOC_CALL deallocate(void* ptr, size_t size);
		MPMALLOC_ATTR size_t MPMALLOC_CALL block_size_of(size_t size);
	}

	namespace shared_cache
	{
		[[nodiscard]] MPMALLOC_ATTR void* MPMALLOC_CALL try_allocate(size_t size);
		[[nodiscard]] MPMALLOC_ATTR void* MPMALLOC_CALL allocate(size_t size);
		MPMALLOC_ATTR void MPMALLOC_CALL deallocate(void* ptr, size_t size);
		MPMALLOC_ATTR size_t MPMALLOC_CALL block_size_of(size_t size);
		//MPMALLOC_ATTR size_t MPMALLOC_CALL size_of(const void* ptr, size_t size);
	}

	namespace thread_cache
	{
		[[nodiscard]] MPMALLOC_ATTR void* MPMALLOC_CALL try_allocate(size_t size);
		[[nodiscard]] MPMALLOC_ATTR void* MPMALLOC_CALL allocate(size_t size);
		MPMALLOC_ATTR void MPMALLOC_CALL deallocate(void* ptr, size_t size);
		MPMALLOC_ATTR size_t MPMALLOC_CALL block_size_of(size_t size);
		//MPMALLOC_ATTR size_t MPMALLOC_CALL size_of(const void* ptr, size_t size);
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
	MPMALLOC_INLINE_ALWAYS size_t optional(bool condition, size_t value)
	{
		return (size_t)((-(ptrdiff_t)condition) & (ptrdiff_t)value);
	}

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
	MPMALLOC_INLINE_ALWAYS static bool bit_test(T mask, uint_fast8_t index)
	{
		return (mask & ((T)1 << (T)index)) != (T)0;
	}

	template <typename T>
	MPMALLOC_INLINE_ALWAYS static void bit_set(T& mask, uint_fast8_t index)
	{
		mask |= ((T)1 << index);
	}

	template <typename T>
	MPMALLOC_INLINE_ALWAYS static void bit_reset(T& mask, uint_fast8_t index)
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

	static constexpr uint8_t constexpr_log2(size_t value)
	{
#if UINT32_MAX == UINTPTR_MAX
		constexpr uint8_t lookup[] = { 0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30, 8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31 };
		value |= value >> 1;
		value |= value >> 2;
		value |= value >> 4;
		value |= value >> 8;
		value |= value >> 16;
		return (uint8_t)lookup[(uint32_t)(value * 0x07C4ACDD) >> 27];
#else
		constexpr uint8_t lookup[] =
		{
			63, 0, 58, 1, 59, 47, 53, 2, 60, 39, 48, 27, 54, 33, 42, 3, 61, 51, 37, 40, 49, 18, 28, 20, 55, 30, 34, 11, 43, 14, 22, 4,
			62, 57, 46, 52, 38, 26, 32, 41, 50, 36, 17, 19, 29, 10, 13, 21, 56, 45, 25, 31, 35, 16, 9, 12, 44, 24, 15, 8, 23, 7, 6, 5
		};
		value |= value >> 1;
		value |= value >> 2;
		value |= value >> 4;
		value |= value >> 8;
		value |= value >> 16;
		value |= value >> 32;
		return (uint8_t)lookup[((uint64_t)((value - (value >> 1)) * 0x07EDD5E59A4E28C2)) >> 58];
#endif
	}

	namespace params
	{
		static constexpr size_t cache_line_size = std::hardware_constructive_interference_size;
		static constexpr uint8_t cache_line_size_log2 = constexpr_log2(cache_line_size);

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
		}
	}

	MPMALLOC_INLINE_ALWAYS static size_t chunk_size_of(size_t size)
	{
		size *= params::BLOCK_ALLOCATOR_MAX_CAPACITY;
		MPMALLOC_UNLIKELY_IF(size > params::chunk_size)
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

#ifndef MPMALLOC_32BIT
		using WaitOnAddress_t = decltype(WaitOnAddress)*;
		using WakeByAddressSingle_t = decltype(WakeByAddressSingle)*;
		static WaitOnAddress_t wait_on_addr;
		static WakeByAddressSingle_t wake_by_addr;
#endif

		static void init()
		{
			HMODULE m = GetModuleHandle(TEXT("KernelBase.DLL"));
			MPMALLOC_INVARIANT(m != NULL);
			aligned_allocate = (decltype(VirtualAlloc2)*)GetProcAddress(m, "VirtualAlloc2");
#ifndef MPMALLOC_32BIT
			m = GetModuleHandle(TEXT("Synchronization.lib"));
			wait_on_addr = (WaitOnAddress_t)GetProcAddress(m, "WaitOnAddress");
			wake_by_addr = (WakeByAddressSingle_t)GetProcAddress(m, "WakeByAddressSingle");
#endif
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

		MPMALLOC_INLINE_ALWAYS static void this_thread_yield()
		{
			(void)SwitchToThread();
		}

		MPMALLOC_INLINE_ALWAYS static uint32_t this_processor_index()
		{
			PROCESSOR_NUMBER k;
			GetCurrentProcessorNumberEx(&k);
			return (k.Group << 6) | k.Number;
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

		template <typename T, typename U>
		MPMALLOC_INLINE_ALWAYS static void futex_await(T& value, U prior)
		{
			wait_on_addr(&value, &prior, sizeof(value), INFINITE);
		}

		template <typename T>
		MPMALLOC_INLINE_ALWAYS static void futex_signal(T& value)
		{
			wake_by_addr(&value);
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

	namespace statistics
	{
		MPMALLOC_SHARED_ATTR static std::atomic_size_t used_memory;
		MPMALLOC_SHARED_ATTR static std::atomic_size_t total_memory;
		MPMALLOC_SHARED_ATTR static std::atomic_size_t used_vas;
		MPMALLOC_SHARED_ATTR static std::atomic_size_t total_vas;

		MPMALLOC_ATTR size_t MPMALLOC_CALL used_physical_memory()
		{
			return used_memory.load(std::memory_order_acquire);
		}

		MPMALLOC_ATTR size_t MPMALLOC_CALL total_physical_memory()
		{
			return total_memory.load(std::memory_order_acquire);
		}

		MPMALLOC_ATTR size_t MPMALLOC_CALL used_address_space()
		{
			return used_vas.load(std::memory_order_acquire);
		}

		MPMALLOC_ATTR size_t MPMALLOC_CALL total_address_space()
		{
			return total_vas.load(std::memory_order_acquire);
		}
	}

	template <typename F>
	struct scoped_callback
	{
		F callback;

		constexpr scoped_callback(F&& callback)
			: callback(std::forward<F>(callback))
		{
		}

		~scoped_callback()
		{
			callback();
		}
	};

	template <typename T>
	struct MPMALLOC_SHARED_ATTR cache_aligned
	{
		T value;
	};

	struct free_list_node
	{
		free_list_node* next;
	};

	// Plain old free-list.
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

	// MPSC Wait-free free-list, AKA bottleneck C:
	struct recovered_list
	{
		std::atomic<free_list_node*> head;

		MPMALLOC_INLINE_ALWAYS void push(void* ptr)
		{
			free_list_node* new_head = (free_list_node*)ptr;
			free_list_node* prior = head.exchange(new_head, std::memory_order_acquire);
			if (prior != nullptr)
			{
				prior->next = new_head;
				std::atomic_thread_fence(std::memory_order_release);
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

	struct tagged_chunk_ptr
	{
		size_t mask;

		template <typename T>
		MPMALLOC_INLINE_ALWAYS void set(T* ptr, size_t tag)
		{
			MPMALLOC_INVARIANT(((size_t)ptr & params::chunk_size_mask) == 0);
			mask = (size_t)ptr | (tag & params::chunk_size_mask);
		}

		MPMALLOC_INLINE_ALWAYS size_t tag() const
		{
			return mask & params::chunk_size_mask;
		}

		template <typename T = void>
		MPMALLOC_INLINE_ALWAYS T* ptr() const
		{
			return (T*)(mask & ~params::chunk_size_mask);
		}
	};

	// MPMC Lock-free free-list, AKA bottleneck C':
	struct shared_chunk_list
	{
		std::atomic<tagged_chunk_ptr> head;

		MPMALLOC_INLINE_ALWAYS void push(void* ptr)
		{
			free_list_node* new_head = (free_list_node*)ptr;
			tagged_chunk_ptr prior, desired;
			for (;; MPMALLOC_SPIN_WAIT)
			{
				prior = head.load(std::memory_order_acquire);
				new_head->next = prior.ptr<free_list_node>();
				desired.set(new_head, prior.tag() + 1);
				if (head.compare_exchange_weak(prior, desired, std::memory_order_release, std::memory_order_relaxed))
					break;
			}
		}

		MPMALLOC_INLINE_ALWAYS void* pop()
		{
			tagged_chunk_ptr prior, desired;
			for (;; MPMALLOC_SPIN_WAIT)
			{
				prior = head.load(std::memory_order_acquire);
				free_list_node* ptr = prior.ptr<free_list_node>();
				if (ptr == nullptr)
					return nullptr;
				desired.set(ptr->next, prior.tag() + 1);
				if (head.compare_exchange_weak(prior, desired, std::memory_order_acquire, std::memory_order_relaxed))
					return ptr;
			}
		}

		MPMALLOC_INLINE_ALWAYS free_list_node* pop_all()
		{
			tagged_chunk_ptr prior = head.exchange({}, std::memory_order_acquire);
			return prior.ptr<free_list_node>();
		}

		MPMALLOC_INLINE_ALWAYS void* peek()
		{
			return head.load(std::memory_order_acquire).ptr();
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

	namespace hazard_ptr
	{
		static constexpr uint32_t MAX_THREADS = 16; // 16*256 = 4096 max threads accessing a parallel_chunk_map, also useful in match_vector.

		struct MPMALLOC_SHARED_ATTR node
		{
			std::atomic<void*> pointer;
			
			MPMALLOC_INLINE_ALWAYS void protect(void* ptr)
			{
				pointer.store(ptr, std::memory_order_release);
			}

			MPMALLOC_INLINE_ALWAYS void release()
			{
				pointer.store(nullptr, std::memory_order_release);
			}
		};

		struct shared_context
		{
			node nodes[MAX_THREADS];

			MPMALLOC_INLINE_ALWAYS node* acquire()
			{
				for (;; os::this_thread_yield())
				{
					for (node& e : nodes)
					{
						void* prior = e.pointer.load(std::memory_order_acquire);
						if (prior == nullptr && e.pointer.compare_exchange_strong(prior, (void*)UINTPTR_MAX, std::memory_order_release, std::memory_order_relaxed))
							return &e;
					}
				}
			}
		};

		struct local_context
		{
			void** bump;
			void* unreclaimed[MAX_THREADS];

			void init()
			{
				bump = unreclaimed;
			}

			static uint8_t bad_hash(size_t key)
			{
				key >>= params::cache_line_size_log2;
				uint8_t hash = (uint8_t)key;
				key >>= 8;
				hash ^= (uint8_t)key;
				return hash;
			}

			uint32_t match_vector(uint8_t* hints, uint8_t hint, uint8_t count)
			{
				uint32_t mask = _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_load_si128((const __m128i*)hints), _mm_set1_epi8(hint)));
				mask |= (1UI32 << count) - 1UI32;
				if (mask == 0)
					return MAX_THREADS;
				return mask;
			}

			template <typename F>
			bool try_collect(shared_context& parent, F&& destructor)
			{
				uint8_t count = 0;
				alignas (16) uint8_t hints[MAX_THREADS];
				void* ptrs[MAX_THREADS];
				for (auto& n : parent.nodes)
				{
					void* ptr = n.pointer.load(std::memory_order_acquire);
					if (ptr == nullptr)
						continue;
					hints[count] = bad_hash((size_t)ptr);
					ptrs[count] = ptr;
					++count;
				}

				uint_fast8_t reclaimed_count = 0;
				for (auto i = unreclaimed; i != bump; ++i)
				{
					uint8_t hint = bad_hash((size_t)*i);
					uint8_t j;
					uint32_t mask = match_vector(hints, hint, count);
					bool found = false;
					for (; mask != 0 && !found; bit_reset(mask, j))
					{
						j = find_first_set(mask);
						if (ptrs[j] == *i)
							found = true;
					}
					if (!found)
					{
						++reclaimed_count;
						--bump;
						destructor(*i);
						if (i != bump)
							*i = *bump;
					}
				}
				return reclaimed_count != 0;
			}

			template <typename F>
			void collect(shared_context& parent, F&& destructor)
			{
				for (;; os::this_thread_yield())
					if (try_collect(parent, destructor))
						break;
			}

			template <typename F>
			void retire(shared_context& parent, void* ptr, F&& destructor)
			{
				if (bump == unreclaimed + MAX_THREADS)
					collect(parent, destructor);
				*bump = ptr;
				++bump;
				try_collect(parent, std::forward<F>(destructor));
			}
		};
	}
	
	MPMALLOC_INLINE_ALWAYS static size_t hash_chunk_ptr(size_t key, size_t seed)
	{
		key >>= params::chunk_size_log2;
#ifdef MPMALLOC_DEBUG
		key ^= seed;
#endif
		key ^= key >> 32;
		key *= 0xd6e8feb86659fd93ULL;
		key ^= key >> 32;
		key *= 0xd6e8feb86659fd93ULL;
		key ^= key >> 32;
		return key;
	}

	struct group_ctrl
	{
		static constexpr uint8_t GROUP_SIZE = 7;

		uint8_t count;
		uint8_t hints[GROUP_SIZE];
	};

	struct group_type
	{
		enum : uint8_t
		{
			INSERTED = 128
		};

		std::atomic<group_ctrl> ctrl;
		std::atomic<size_t> keys[group_ctrl::GROUP_SIZE];

		uint_fast8_t exclusive_insert(size_t key, uint8_t hint)
		{
			group_ctrl prior = non_atomic_load(ctrl);
#ifdef MPMALLOC_DEBUG
			for (uint8_t i = 0; i != prior.count; ++i)
				MPMALLOC_UNLIKELY_IF(prior.hints[i] == hint)
					MPMALLOC_INVARIANT(non_atomic_load(keys[i]) != key);
#endif
			MPMALLOC_UNLIKELY_IF(prior.count == group_ctrl::GROUP_SIZE)
				return group_ctrl::GROUP_SIZE;
			group_ctrl desired = prior;
			desired.hints[desired.count] = hint;
			++desired.count;
			non_atomic_store(ctrl, desired);
			non_atomic_store(keys[prior.count], key);
			return prior.count;
		}

		uint_fast8_t find_or_insert(size_t key, uint8_t hint)
		{
			group_ctrl prior;
			for (;; MPMALLOC_SPIN_WAIT)
			{
				prior = ctrl.load(std::memory_order_acquire);
				for (uint8_t i = 0; i != prior.count; ++i)
					MPMALLOC_LIKELY_IF(prior.hints[i] == hint && keys[i].load(std::memory_order_acquire) == key)
						return i;
				MPMALLOC_UNLIKELY_IF(prior.count == group_ctrl::GROUP_SIZE)
					return group_ctrl::GROUP_SIZE;
				group_ctrl desired = prior;
				desired.hints[desired.count] = hint;
				++desired.count;
				MPMALLOC_LIKELY_IF(ctrl.compare_exchange_weak(prior, desired, std::memory_order_acquire, std::memory_order_relaxed))
					break;
			}
			keys[prior.count].store(key, std::memory_order_release);
			return prior.count | INSERTED;
		}

		uint_fast8_t find(size_t key, uint8_t hint) const
		{
			group_ctrl prior;
			for (;; MPMALLOC_SPIN_WAIT)
			{
				prior = ctrl.load(std::memory_order_acquire);
				for (uint8_t i = 0; i != prior.count; ++i)
					MPMALLOC_LIKELY_IF(prior.hints[i] == hint && keys[i].load(std::memory_order_acquire) == key)
						return i;
				group_ctrl current = ctrl.load(std::memory_order_acquire);
				MPMALLOC_UNLIKELY_IF(memcmp(&prior, &current, 8) != 0)
					return group_ctrl::GROUP_SIZE;
				prior = current;
			}
		}
	};

	template <typename T>
	struct MPMALLOC_SHARED_ATTR parallel_chunk_map_shard
	{
		struct MPMALLOC_SHARED_ATTR parallel_chunk_map_shard_header
		{
			std::atomic_size_t used_count;
			size_t group_mask;

			static size_t min_group_count()
			{
				constexpr size_t DIVISOR = sizeof(group_type) + sizeof(T) * 7;
				return params::chunk_size / DIVISOR;
			}

			static size_t buffer_size(size_t group_count)
			{
				size_t size = sizeof(parallel_chunk_map_shard_header);
				size += group_count * sizeof(group_type);
				size += sizeof(T) * group_ctrl::GROUP_SIZE;
				return MPMALLOC_ALIGN_ROUND(size, params::chunk_size);
			}

			static parallel_chunk_map_shard_header* allocate(size_t group_count)
			{
				size_t size = buffer_size(group_count);
				parallel_chunk_map_shard_header* r = (parallel_chunk_map_shard_header*)backend::allocate(size);
				(void)memset(r, 0, size);
				r->group_mask = group_count - 1;
				return r;
			}

			static bool is_valid_load_factor(size_t used_count, size_t capacity)
			{
				return used_count >= (((capacity * group_ctrl::GROUP_SIZE) * MPMALLOC_MAX_LOAD_FACTOR_NUMERATOR) / MPMALLOC_MAX_LOAD_FACTOR_DENOMINATOR);
			}

			bool should_expand() const
			{
				return is_valid_load_factor(used_count.load(std::memory_order_acquire), group_mask + 1);
			}

			group_type* groups() const
			{
				return (group_type*)(this + 1);
			}

			T* values() const
			{
				return (T*)(groups() + (group_mask + 1));
			}

			T* exclusive_insert(size_t key, size_t hash)
			{
				uint8_t i;
				size_t group_index;
				uint8_t hint = (uint8_t)hash;
				hash >>= 8;
				group_index = hash;
				for (;; ++group_index)
				{
					group_index &= group_mask;
					group_type& group = groups()[group_index];
					i = group.exclusive_insert(key, hint);
					MPMALLOC_LIKELY_IF(i != group_ctrl::GROUP_SIZE)
						break;
				}
				MPMALLOC_LIKELY_IF((i & group_type::INSERTED) != 0)
					non_atomic_store(used_count, non_atomic_load(used_count) + 1);
				size_t value_index = group_index * 7 + (i & ~group_type::INSERTED);
				return &values()[value_index];
			}

			template <typename F>
			void for_each(F&& function)
			{
			}

			template <typename F>
			void for_each_value(F&& function)
			{
			}
		};

		thread_local inline static hazard_ptr::local_context local_hp_ctx;

		MPMALLOC_SHARED_ATTR hazard_ptr::shared_context shared_ctx;
		MPMALLOC_SHARED_ATTR std::atomic<parallel_chunk_map_shard_header*> map;

		MPMALLOC_INLINE_ALWAYS static size_t get_hash_seed()
		{
			return 0;
		}

		MPMALLOC_INLINE_NEVER parallel_chunk_map_shard_header* expand(parallel_chunk_map_shard_header* prior, hazard_ptr::node* n)
		{
			parallel_chunk_map_shard_header* new_map;
			size_t new_group_count = 0;
			while (true)
			{
				if (prior == nullptr)
				{
					new_group_count = parallel_chunk_map_shard_header::min_group_count();
				}
				else
				{
					new_group_count = ((prior->group_mask + 1) * 2);
				}

				parallel_chunk_map_shard_header* current = map.load(std::memory_order_acquire);
				if (prior != current)
				{
					for (;; MPMALLOC_SPIN_WAIT)
					{
						prior = current;
						n->protect(prior);
						current = map.load(std::memory_order_acquire);
						if (prior == current)
							break;
					}
					if (prior != nullptr && !prior->should_expand())
						return prior;
				}

				new_map = parallel_chunk_map_shard_header::allocate(new_group_count);
				prior->for_each([&](size_t key, T& value)
				{
					size_t hash = hash_chunk_ptr(key, get_hash_seed());
					T* target = prior->exclusive_insert(key, hash);
				});
				n->protect(new_map);

				if (prior != nullptr)
				{
					local_hp_ctx.retire(shared_ctx, prior, [](void* ptr)
					{
						parallel_chunk_map_shard_header* m = (parallel_chunk_map_shard_header*)ptr;
						backend::deallocate(m, parallel_chunk_map_shard_header::buffer_size(m->group_mask + 1));
					});
				}
				return new_map;
			}
		}

		T* find_or_insert(size_t key, size_t hash)
		{
			while (true)
			{
				hazard_ptr::node* n = shared_ctx.acquire();
				scoped_callback callback = [&]
				{
					n->release();
				};
				parallel_chunk_map_shard_header* prior = map.load(std::memory_order_acquire);
				uint8_t i;
				size_t group_index;
				uint8_t hint = (uint8_t)hash;
				hash >>= 8;
				for (;; MPMALLOC_SPIN_WAIT)
				{
					n->protect(prior);
					parallel_chunk_map_shard_header* current = map.load(std::memory_order_acquire);
					if (prior == current)
						break;
					prior = current;
				}
				if (prior == nullptr || prior->should_expand())
					prior = expand(prior, n);
				group_index = hash;
				for (;; ++group_index)
				{
					group_index &= prior->group_mask;
					group_type& group = prior->groups()[group_index];
					i = group.find_or_insert(key, hint);
					MPMALLOC_LIKELY_IF(i != group_ctrl::GROUP_SIZE)
					{
						MPMALLOC_LIKELY_IF((i & group_type::INSERTED) != 0)
							(void)prior->used_count.fetch_add(1, std::memory_order_relaxed);
						size_t value_index = group_index * 7 + (i & ~group_type::INSERTED);
						return &prior->values()[value_index];
					}
					if (map.load(std::memory_order_acquire) != prior)
						break;
				}
			}
		}

		T* find(size_t key, size_t hash)
		{
			while (true)
			{
				hazard_ptr::node* n = shared_ctx.acquire();
				scoped_callback callback = [&]
				{
					n->release();
				};
				parallel_chunk_map_shard_header* prior = map.load(std::memory_order_acquire);
				for (;; MPMALLOC_SPIN_WAIT)
				{
					if (prior == nullptr)
						return nullptr;
					n->protect(prior);
					parallel_chunk_map_shard_header* current = map.load(std::memory_order_acquire);
					if (prior == current)
						break;
					prior = current;
				}
				uint8_t hint = (uint8_t)hash;
				hash >>= 8;
				size_t group_index = hash;
				uint8_t i;
				for (;; ++group_index)
				{
					group_index &= prior->group_mask;
					group_type& group = prior->groups()[group_index];
					i = group.find(key, hint);
					MPMALLOC_LIKELY_IF(i != group_ctrl::GROUP_SIZE)
					{
						size_t value_index = group_index * 7 + i;
						return &prior->values()[value_index];
					}
				}
				if (map.load(std::memory_order_acquire) != prior)
					break;
			}
		}

		template <typename F>
		void for_each(F&& function)
		{
			hazard_ptr::node* n = shared_ctx.acquire();
			scoped_callback callback = [&]
			{
				n->release();
			};
			parallel_chunk_map_shard_header* prior = map.load(std::memory_order_acquire);
			for (;; MPMALLOC_SPIN_WAIT)
			{
				if (prior == nullptr)
					return;
				n->protect(prior);
				parallel_chunk_map_shard_header* current = map.load(std::memory_order_acquire);
				if (prior == current)
					break;
				prior = current;
			}
			prior->for_each(function);
		}

		template <typename F>
		void for_each_value(F&& function)
		{
			hazard_ptr::node* n = shared_ctx.acquire();
			scoped_callback callback = [&]
			{
				n->release();
			};
			parallel_chunk_map_shard_header* prior = map.load(std::memory_order_acquire);
			for (;; MPMALLOC_SPIN_WAIT)
			{
				if (prior == nullptr)
					return;
				n->protect(prior);
				parallel_chunk_map_shard_header* current = map.load(std::memory_order_acquire);
				if (prior == current)
					break;
				prior = current;
			}
			prior->for_each_value(function);
		}
	};

	template <typename T>
	struct parallel_chunk_map
	{
		parallel_chunk_map_shard<T> shards[256];

		MPMALLOC_INLINE_ALWAYS T* find_or_insert(size_t key)
		{
			size_t hash_seed = parallel_chunk_map_shard<T>::get_hash_seed();
			size_t hash = hash_chunk_ptr(key, hash_seed);
			return shards[(uint8_t)hash].find_or_insert(key, hash >> 8);
		}

		MPMALLOC_INLINE_ALWAYS T* find(size_t key)
		{
			size_t hash_seed = parallel_chunk_map_shard<T>::get_hash_seed();
			size_t hash = hash_chunk_ptr(key, hash_seed);
			return shards[(uint8_t)hash].find(key, hash >> 8);
		}

		template <typename F>
		MPMALLOC_INLINE_ALWAYS void map(F&& function)
		{
			for (parallel_chunk_map_shard<T>& shard : shards)
				shard.for_each_value(function);
		}
	};
#endif

	namespace large_cache
	{
		MPMALLOC_ATTR size_t MPMALLOC_CALL block_size_of(size_t size)
		{
			size_t r = MPMALLOC_ALIGN_ROUND(size, params::chunk_size);
			MPMALLOC_UNLIKELY_IF(r < params::chunk_size)
				r = 0;
			return r;
		}

#ifndef MPMALLOC_64BIT
		static size_t bin_count;
		static shared_chunk_list* bins;

		MPMALLOC_SHARED_ATTR static std::atomic_size_t min_bin = UINTPTR_MAX;
		MPMALLOC_SHARED_ATTR static std::atomic_size_t max_bin = 0;

		MPMALLOC_ATTR void MPMALLOC_CALL init()
		{
			bin_count = (size_t)1 << (32 - params::chunk_size_log2);
			size_t buffer_size = sizeof(shared_chunk_list) * bin_count;
			bins = (shared_chunk_list*)backend::allocate_chunk_aligned(buffer_size);
		}

		MPMALLOC_ATTR void MPMALLOC_CALL finalize()
		{
			size_t buffer_size = sizeof(shared_chunk_list) << bin_count;
			backend::deallocate(bins, buffer_size);
		}

		MPMALLOC_ATTR void* MPMALLOC_CALL try_allocate(size_t size)
		{
			size >>= params::chunk_size_log2;
			--size;
			return bins[size].pop();
		}

		MPMALLOC_ATTR void* MPMALLOC_CALL allocate(size_t size)
		{
			void* r = try_allocate(size);
			MPMALLOC_UNLIKELY_IF(r == nullptr)
			{
				r = backend::allocate_chunk_aligned(MPMALLOC_ALIGN_ROUND(size, params::chunk_size));
				(void)statistics::used_vas.fetch_add(optional(r != nullptr, size), std::memory_order_relaxed);
			}
			return r;
		}

		MPMALLOC_ATTR void MPMALLOC_CALL deallocate(void* ptr, size_t size)
		{
			size >>= params::chunk_size_log2;
			--size;
			bins[size].push(ptr);
			size_t prior = min_bin.load(std::memory_order_acquire);
			MPMALLOC_UNLIKELY_IF(size < prior)
				(void)min_bin.compare_exchange_strong(prior, size, std::memory_order_release, std::memory_order_relaxed);
			prior = max_bin.load(std::memory_order_acquire);
			++size;
			MPMALLOC_UNLIKELY_IF(size > prior)
				(void)max_bin.compare_exchange_strong(prior, size, std::memory_order_release, std::memory_order_relaxed);
		}

		template <typename F>
		MPMALLOC_INLINE_ALWAYS void for_each_bin(F&& function)
		{
			size_t i = min_bin.load(std::memory_order_acquire);
			MPMALLOC_UNLIKELY_IF(i == UINT32_MAX)
				return;
			for (; i != max_bin.load(std::memory_order_acquire); ++i)
				function(bins[i], i);
		}
#else
		MPMALLOC_SHARED_ATTR static shared_chunk_list single_chunk_bin;

		static parallel_chunk_map<shared_chunk_list> lookup;

		MPMALLOC_ATTR void MPMALLOC_CALL init()
		{
		}

		MPMALLOC_ATTR void MPMALLOC_CALL finalize()
		{
		}

		MPMALLOC_ATTR void* MPMALLOC_CALL try_allocate(size_t size)
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

		MPMALLOC_ATTR void* MPMALLOC_CALL allocate(size_t size)
		{
			void* r = try_allocate(size);
			MPMALLOC_UNLIKELY_IF(r == nullptr)
				r = backend::allocate_chunk_aligned(size);
			return r;
		}

		MPMALLOC_ATTR void MPMALLOC_CALL deallocate(void* ptr, size_t size)
		{
			size >>= params::chunk_size_log2;
			--size;
			MPMALLOC_LIKELY_IF(size == 0)
				return single_chunk_bin.push(ptr);
			lookup.find_or_insert(size)->push(ptr);
		}

		template <typename F>
		MPMALLOC_INLINE_ALWAYS void for_each_bin(F&& function)
		{
			lookup.map(std::forward<F>(function));
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
			std::atomic_uint32_t begin_free_mask;
			std::atomic_uint32_t free_count;
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
		static parallel_chunk_map<shared_block_allocator> lookup;
#endif
		static shared_allocator_list* bins;
		static shared_block_allocator_recover_list* recovered;

		MPMALLOC_ATTR void MPMALLOC_CALL init()
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

		MPMALLOC_ATTR void MPMALLOC_CALL finalize()
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

		MPMALLOC_ATTR void* MPMALLOC_CALL try_allocate(size_t size)
		{
			uint_fast8_t sc = floor_log2(size) - params::page_size_log2;
			return try_allocate_impl(sc);
		}

		MPMALLOC_ATTR void* MPMALLOC_CALL allocate(size_t size)
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

		MPMALLOC_ATTR void MPMALLOC_CALL deallocate(void* ptr, size_t size)
		{
#ifndef MPMALLOC_64BIT
			lookup[(size_t)ptr >> params::chunk_size_log2].deallocate(ptr);
#else
			lookup.find_or_insert((size_t)ptr)->deallocate(ptr);
#endif
		}

		MPMALLOC_ATTR size_t MPMALLOC_CALL block_size_of(size_t size)
		{
			return round_pow2(size);
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
			cache_aligned<recovered_list> small_recovered[params::SIZE_CLASS_COUNT];
			free_list* large_bins;
			cache_aligned<recovered_list>* large_recovered;
		};

		thread_local static thread_cache_state here;

		MPMALLOC_INLINE_NEVER static uint_fast8_t size_class_of(size_t size)
		{
			for (uint_fast8_t i = 0; i != params::SIZE_CLASS_COUNT; ++i)
				MPMALLOC_UNLIKELY_IF(params::SMALL_SIZE_CLASSES[i] >= size)
					return i;
			MPMALLOC_UNREACHABLE;
		}

		MPMALLOC_INLINE_NEVER static size_t block_size_of_unsafe(size_t size)
		{
			return params::SMALL_SIZE_CLASSES[size_class_of(size)];
		}

		MPMALLOC_ATTR size_t MPMALLOC_CALL block_size_of(size_t size)
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

		MPMALLOC_ATTR void* MPMALLOC_CALL try_allocate(size_t size)
		{
			uint_fast8_t sc = size_class_of(size);
			return try_allocate_impl(sc);
		}

		MPMALLOC_ATTR void* MPMALLOC_CALL allocate(size_t size)
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

		MPMALLOC_ATTR void MPMALLOC_CALL deallocate(void* ptr, size_t size)
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

		MPMALLOC_ATTR void MPMALLOC_CALL init()
		{
		}

		MPMALLOC_ATTR void MPMALLOC_CALL finalize()
		{
		}
	}

	MPMALLOC_ATTR void MPMALLOC_CALL init(const init_options* options)
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

	MPMALLOC_ATTR void MPMALLOC_CALL finalize()
	{
		shared_cache::finalize();
		large_cache::finalize();
		backend::init();
	}

	MPMALLOC_ATTR void MPMALLOC_CALL init_thread()
	{
		thread_cache::init();
	}

	MPMALLOC_ATTR void MPMALLOC_CALL finalize_thread()
	{
		thread_cache::finalize();
	}

	MPMALLOC_ATTR void* MPMALLOC_CALL allocate(size_t size)
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

	MPMALLOC_ATTR bool MPMALLOC_CALL try_expand(void* ptr, size_t old_size, size_t new_size)
	{
		size_t rounded_old_size = block_size_of(old_size);
		return rounded_old_size >= new_size;
	}

	MPMALLOC_ATTR void* MPMALLOC_CALL reallocate(void* ptr, size_t old_size, size_t new_size)
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

	MPMALLOC_ATTR void MPMALLOC_CALL deallocate(void* ptr, size_t size)
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

	MPMALLOC_ATTR size_t MPMALLOC_CALL block_size_of(size_t size)
	{
		MPMALLOC_LIKELY_IF(size <= params::page_size)
			return thread_cache::block_size_of(size);
		else MPMALLOC_LIKELY_IF(size < params::chunk_size)
			return shared_cache::block_size_of(size);
		else
			return large_cache::block_size_of(size);
	}

	MPMALLOC_ATTR size_t MPMALLOC_CALL trim()
	{
		size_t freed_bytes = 0;
		large_cache::for_each_bin([&](shared_chunk_list& bin, size_t bin_index)
		{
			size_t size = (bin_index + 1) << params::chunk_size_log2;
			size_t count = 0;
			free_list_node* next;
			for (free_list_node* n = bin.pop_all(); n != nullptr; n = next)
			{
				++count;
				next = n->next;
				backend::deallocate(n, size);
			}
			freed_bytes += count * size;
		});
		return freed_bytes;
	}

	MPMALLOC_ATTR backend_options MPMALLOC_CALL default_backend()
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

	MPMALLOC_ATTR backend_options MPMALLOC_CALL current_backend()
	{
		backend_options r;
		r.init = backend::init;
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

	MPMALLOC_ATTR platform_information MPMALLOC_CALL platform_info()
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