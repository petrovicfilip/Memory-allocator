#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <stdbool.h>
#define PAGE 4096

typedef struct chunk chunk;
typedef struct heap_info heap_info;
typedef struct mapped_region__border_arr mapped_region__border_arr; 

struct chunk
{
    size_t size;
    size_t prev_size;
    chunk* next_free;
    bool used;
};

struct heap_info
{
    chunk* first_free_chunk;
    size_t available;
    void* first_region;
};

heap_info global_heap_info = { NULL, 0, NULL };

// 16B je ovaj struktura
struct mapped_region__border_arr
{
    size_t size;
    void* next;
};

bool make_first_mapped_region(void* mem_addr, size_t total)
{
    void* start = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (start == MAP_FAILED)
        return false;
    printf("Start adr.: %p\n", start);
    void** p = (void**)start; 
    printf("OPREM: %p\n", p);

    global_heap_info.first_region = start;

    mapped_region__border_arr* fmr = (mapped_region__border_arr*)start;
    fmr->next = NULL;

    void** beg_addr = (void**)((char*)start + sizeof(mapped_region__border_arr));
    *beg_addr = mem_addr;
    void** end_addr = (void**)((char*)beg_addr + sizeof(void*));
    *end_addr = (void*)((char*)mem_addr + total) ;
    
    fmr->size = 2;

    return true;
}

bool extend_mapped_region_list(void* mem, size_t total)
{
    // treba opet pozvati mmap za novi region, dodati prosledjenu adresu u novi region, i dodati je na vrh lancane liste(za sad... mozda cu i na rep cu vidim)
    void* start = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (start == MAP_FAILED)
        return false;

    mapped_region__border_arr* nmr = (mapped_region__border_arr*)start;
    nmr->next = global_heap_info.first_region;
    global_heap_info.first_region = start;

    void** beg_addr = (void**)((char*)start + sizeof(mapped_region__border_arr));
    *beg_addr = mem;
    void** end_addr = (void**)((char*)beg_addr + sizeof(void*));
    *end_addr = (void*)((char*)mem + total);

    nmr->size = 2;
    
    return true;
}

bool add_mapped_region(void* mem_addr, size_t total)
{
    void* block_of_region_list = global_heap_info.first_region;
    
    while(block_of_region_list != NULL)
    {
        mapped_region__border_arr* dummy = (mapped_region__border_arr*)block_of_region_list; 
        size_t size = dummy->size;
        size_t max_pairs = (PAGE - sizeof(mapped_region__border_arr)) / (2 * sizeof(void*));
        if (size < max_pairs)
        {
            void** beg_addr = (void**)((char*)block_of_region_list + sizeof(mapped_region__border_arr) + (size * sizeof(void*)));
            *beg_addr = mem_addr;
            void** end_addr = (void**)((char*)beg_addr + sizeof(void*));
            *end_addr = (void*)((char*)mem_addr + total) ;
            dummy->size += 2;
            return true;
        }

        block_of_region_list = dummy->next;
    }
    return extend_mapped_region_list(mem_addr, total);
}

bool implemented = false;

// alloc_m ce da zove kad nema vise memorije na heap-u
void* extend_heap(size_t alloc_size, void** start)
{
    void* mem;
    size_t heap_size;
    size_t total = alloc_size + sizeof(chunk);

    if (total <= PAGE)
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
    if (global_heap_info.first_region == NULL)
       make_first_mapped_region(mem, total);
    else
       add_mapped_region(mem, total);

    printf("Adresa: %p\n", mem);
    // sad se treba skrati prvi blok ako ima visak...
    size_t avail = total - sizeof(chunk);
    int leftover = total - alloc_size - (sizeof(chunk) << 1);
    printf("leftover: %d\n", leftover);
    if (leftover > 0)
    {
        printf("Ostalo: %ld\n", total - alloc_size - sizeof(chunk));
        void* new_free = (char*)mem + sizeof(chunk) + alloc_size;
        chunk* first = (chunk*)mem;
        first->used = true;
        first->prev_size = 0;
        first->size = alloc_size;
        global_heap_info.available += leftover;
        //first->next_free = (chunk*)new_free;
        //first->next_free->used = false;
        //first->next_free->prev_size = alloc_size;

        // prelancavamo, mozda u buducnosti koristiti chunk** u heap_info, cu vidim
        chunk* old_head = global_heap_info.first_free_chunk;
        global_heap_info.first_free_chunk = (chunk*)new_free;
        global_heap_info.first_free_chunk->next_free = old_head;
        global_heap_info.first_free_chunk->prev_size = alloc_size;
        global_heap_info.first_free_chunk->size = leftover;
        global_heap_info.first_free_chunk->used = false;

        //printf("korisceni velicina: %ld\n", first->next_free->prev_size);

        *start = (void*)((char*)mem + sizeof(chunk));
    }
    else
    { // ovde dolazi do unutrasnje fragmentacije jer imamo 32 ili manje bajta ostalo sto je =< header, pa je beskoristan prostor 
      // ali to je za specificne alokacije i <= 32 bajta, tako da nije strasno...
        printf("NULL BURAZERU!!!\n");
        chunk* first = (chunk*)mem;  
        first->used = true;
        first->prev_size = 0;
        first->size = avail;
        first->next_free = NULL; // ne mora, pogledati...
        *start = (void*)((char*)mem + sizeof(chunk));
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
    if (global_heap_info.available < size)
    {
        void* ret;
        extend_heap(size, &ret);
        return ret;
    }
    
    chunk* free_block = global_heap_info.first_free_chunk;
    chunk* bef = NULL;
    chunk* appropriate = NULL;

    // first-fit
    while (free_block != NULL)
    {
        if (free_block->size >= size)
        {
            appropriate = free_block;
            break;
        }
        else
        {
            bef = free_block;
            free_block = free_block->next_free;
        }
    }

    if (!appropriate)
    {
        void* ret;
        extend_heap(size, &ret);
        return ret;
    }
    // moguci slucajevi, nadjeni blok se ne zauzima ceo, i pravi se novi free blok, nadjeni blok se zauzima ceo + poseban slucaj: ova oba slucaja ali da je blok head liste
    if (appropriate != global_heap_info.first_free_chunk)
    {
        size_t leftover = appropriate->size - size;
        
        // NAPISATI LEPSE ZA SAD OVAKO !!!!!!!!!!!!!!!!!!
        if (leftover > 0) // u buducnosti ce vrv biti 0 zamenjena sa MINIMUM_BLOCK_SIZE da ne dobijam blokove velicine svega nekoliko bajtova...
        {
            chunk* next_free = appropriate->next_free;
            appropriate->next_free = NULL;
            appropriate->used = true;
            appropriate->size = size;
            void* new_block_start = (char*)appropriate + sizeof(chunk) + size;
            bef->next_free = (chunk*)new_block_start;
            chunk* nb = (chunk*)new_block_start;
            nb->next_free = next_free;
            nb->size = leftover;
            nb->used = false;
            nb->prev_size = size;
            global_heap_info.available -= size + sizeof(chunk);
        }
        else
        {
            chunk* next_free = appropriate->next_free;
            appropriate->next_free = NULL;
            appropriate->used = true;
            appropriate->size = size;
            bef->next_free = next_free;
            global_heap_info.available -= size + sizeof(chunk);
        }

    }
    else
    {
        size_t leftover = appropriate->size - size;
        if (leftover > 0) // u buducnosti ce vrv biti 0 zamenjena sa MINIMUM_BLOCK_SIZE da ne dobijam blokove velicine svega nekoliko bajtova...
        {
            chunk* next_free = appropriate->next_free;
            appropriate->next_free = NULL;
            appropriate->used = true;
            appropriate->size = size;
            void* new_block_start = (char*)appropriate + sizeof(chunk) + size;
            global_heap_info.first_free_chunk = (chunk*)new_block_start;
            chunk* nb = (chunk*)new_block_start;
            nb->next_free = next_free;
            nb->size = leftover;
            nb->used = false;
            nb->prev_size = size;
            global_heap_info.available -= size + sizeof(chunk);
        }
        else
        {
            chunk* next_free = appropriate->next_free;
            appropriate->next_free = NULL;
            appropriate->used = true;
            appropriate->size = size;
            global_heap_info.first_free_chunk = next_free;
            global_heap_info.available -= size + sizeof(chunk);
        }
    }
    void* ret_addr = (char*)appropriate + sizeof(chunk);
    return (void*)ret_addr;
}

void free_m(void* m)
{
    if (m == NULL)
        return;
    // chunk postaje free i dodaje se na vrh liste free blokova, posle odraditi coalescing sa prethodnim blokom...
    void* chunk_addr = (char*)m - sizeof(chunk);
    chunk* chunkk = (chunk*)chunk_addr;
    chunkk->used = false;


    // coalescing/spajanje sa prethodnim blokom ako je free...
    if (chunkk->prev_size > 0)
    {
        void* bef_chunk_addr = (char*)chunk_addr - chunkk->prev_size - sizeof(chunk);
        chunk* bef_chunk = (chunk*)bef_chunk_addr;
        // treba dodati i proveru da li je zadnji blok u delu mapirane memorije
        // vrv cu to da realizujem kroz staticki niz mapiranja i overhead fje provere ne bi trebalo da bude veci od 1ms, sto je ok, a u vecini slucajeva bice veoma brze
        // bice niz od 256k parova, tj 512k adresa kao tuple - (pocetna, krajnja), sto je minimum 1GB memorije (ako su sva mapiranja 4KB, a realno ako je veliki program bice veca...),
        // ali trebalo bi da zadovoljava, barem za pocetak  
        if (!bef_chunk->used  && implemented)
        {
            bef_chunk->size += chunkk->size + sizeof(chunk);

            chunk* next = (chunk*)((char*)bef_chunk + sizeof(chunk) + bef_chunk->size);
            if (/* check_if_last_chunk() */true)
                next->prev_size = bef_chunk->size;
        }
    }

    chunkk->next_free = global_heap_info.first_free_chunk;
    global_heap_info.first_free_chunk = chunkk;
    //printf("Velicina: %ld\n", chunkk->size);
    return;
}

int main(int argc, char** argv)
{
    printf("%ld\n",sizeof(chunk));
    void* start = NULL;
    //extend_heap(4047, &start);
    // printf("Dostupna memorija heapa -> %ld, Adresa prvog bloka -> %p, Velicina -1 bloka %ld\n", 
    //     global_heap_info.available, global_heap_info.first_free_chunk, global_heap_info.first_free_chunk->prev_size);
    int* a = (int*)alloc_m(sizeof(int) * 1000);
    int s = 0;
    for (int i = 0; i < 1000; i++)
    {
        a[i] = s;
        s++;
    }
    for (int i = 0; i < 1000; i++)
        printf("%d\n", a[i]);
    
    printf("void* velicina: %ld\n", sizeof(void*));
    //make_first_mapped_region();
    printf("%ld", sizeof(mapped_region__border_arr));

    free_m(a);
    return 0;               
}