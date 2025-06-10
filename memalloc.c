#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <stdbool.h>
#define PAGE 4096

typedef struct chunk chunk;
typedef struct heap_info heap_info;

struct chunk
{
    size_t prev_size;
    chunk* next_free;
    bool used;
};

struct heap_info
{
    chunk* first_free_chunk;
    size_t available;
};

heap_info global_heap_info = { NULL, 0 };

// alloc_m ce da zove kad nema vise memorije na heap-u
void* extend_heap(size_t alloc_size)
{
    void* mem;
    size_t heap_size;
    size_t total = alloc_size + sizeof(chunk);

    if(total <= PAGE)
    {
        total = PAGE;
        mem = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    else
    {
        total = ((total + PAGE - 1) / PAGE) * PAGE;

        printf("OPA!\n");
        mem = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    printf("Adresa: %p\n", mem);
    // sad se treba skrati prvi blok ako ima visak...
    size_t avail = total - sizeof(chunk);
    int leftover = total - alloc_size - (sizeof(chunk) << 1);
    printf("leftover: %d\n", leftover);
    if(leftover > 0)
    {
        printf("Ostalo: %ld\n", total - alloc_size - sizeof(chunk));
        void* new_free = (char*)mem + sizeof(chunk) + alloc_size;
        chunk* first = (chunk*)mem;
        first->used = true;
        first->prev_size = 0;
        first->next_free = (chunk*)new_free;
        first->next_free->used = false;
        first->next_free->prev_size = alloc_size;
        printf("korisceni velicina: %ld\n", first->next_free->prev_size);
    }
    else
    { // ovde dolazi do unutrasnje fragmentacije jer imamo 24 ili manje bajta ostalo sto je =< header, pa je beskoristan prostor 
      // ali to je za specificne alokacije i <= 24 bajta, tako da nije strasno...
      printf("NULL BURAZERU!!!\n");
        chunk* first = (chunk*)mem;  
        first->used = true;
        first->prev_size = 0;
        first->next_free = NULL;
        // ovaj blok zauzima ceo mmap() prostor, pa sam po sebi ne moze da ima sledbenika niti ce moci da se coalescuje...
    }

    // if (global_heap_info.first_free_chunk == NULL)
    // {
    //     // inicijalizacija heap-a
    //     global_heap_info.first_free_chunk = (chunk*)mem;
    //     global_heap_info.available = total - sizeof(chunk); // alloc_size
    //     global_heap_info.first_free_chunk->prev_size = 0;
    //     global_heap_info.first_free_chunk->used = false; // true
    //     global_heap_info.first_free_chunk->next_free = NULL;
    // }
    // else
    // {
    //     // TODO
    // }
}

void* alloc_m(size_t size)
{
    return NULL;
}

void free_m(void* m)
{
    return;
}

int main(int argc, char** argv)
{
    printf("%ld\n",sizeof(chunk));
    extend_heap(4047);
    // printf("Dostupna memorija heapa -> %ld, Adresa prvog bloka -> %p, Velicina -1 bloka %ld\n", 
    //     global_heap_info.available, global_heap_info.first_free_chunk, global_heap_info.first_free_chunk->prev_size);
    return 0;               
}