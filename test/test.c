#define MP_IMPLEMENTATION
#include "../mp_malloc.h"
#include <assert.h>
#include <stdio.h>

static const int nallocs = 1000;
static void* allocs[nallocs];
static size_t sizes[nallocs];

static void test()
{
    void* ptr;
    ptr = mp_malloc(0);
    assert(ptr == NULL);
    mp_free_sized(ptr, 0);
    srand(43);
    for (size_t i = 0; i != nallocs; ++i)
    {
        sizes[i] = rand();
        allocs[i] = mp_malloc(sizes[i]);
        assert(allocs[i] != NULL);
    }
    for (size_t i = 0; i != nallocs; ++i)
    {
        mp_free_sized(allocs[i], sizes[i]);
    }
}



int main(int argc, const char** args)
{
    mp_init_default();
    mp_thread_init();
    void* ptr = mp_malloc(4096);
    mp_free_sized(ptr, 4096);
    mp_thread_cleanup();
    mp_cleanup();
    puts("Test completed successfully.");
    return 0;
}