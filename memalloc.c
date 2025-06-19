#include "memalloc.h"

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

void* map_memory(size_t total) {
#ifdef _WIN32
    return VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    return mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

void unmap_memory(void* addr, size_t total) {
#ifdef _WIN32
    VirtualFree(addr, 0, MEM_RELEASE);
#else
    munmap(addr, total);
#endif
}

void print_free_blocks()
{
    chunk* block = global_heap_info.first_free_chunk;
    while (block)
    {
        //printf("|| size: %ld, prevsize: %ld, used: %d || -> ", block->size, block->prev_size, block->used);
        block = block->next_free;
    }
    //printf("NULL\n");
}

bool make_first_mapped_region(void* mem_addr, size_t total)
{
    void* start = map_memory(PAGE);
    #ifdef _WIN32
    if (start == NULL)
        return false;
    #else
    if (start == MAP_FAILED)
        return false;
    #endif
    //printf("Start adr.: %p\n", start);
    void** e = (void**)((char*)start + PAGE); 
    //printf("End adr: %p\n", e);

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
    void* start = map_memory(PAGE);
    #ifdef _WIN32
    if (start == NULL)
        return false;
    #else
    if (start == MAP_FAILED)
        return false;
    #endif

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
    
    while (block_of_region_list != NULL)
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

bool chunk_is_last_in_region(chunk* block)
{
    void* chunk_addr = (void*)block;
    void* block_of_region_list = global_heap_info.first_region;

    while (block_of_region_list != NULL)
    {
        mapped_region__border_arr* dummy = (mapped_region__border_arr*)block_of_region_list; 
        size_t size = dummy->size;
        void** a1 = (void**)((char*)block_of_region_list + sizeof(mapped_region__border_arr));
        for (int i = 0; i < size; i += 2)
        {
            void** a2 = (void**)((char*)a1 + sizeof(void*));
            if (chunk_addr >= *a1 && chunk_addr < *a2)
            {
                void* end_of_block = (void*)((char*)chunk_addr + sizeof(chunk) + block->size);
                return end_of_block == *a2;
            }
            a1 = (void**)((char*)a2 + sizeof(void*));
        }
        block_of_region_list = dummy->next;
    }
    // za sigurnost, nikad ne bi trebalo da dodje do ovde...
    return true;
}

size_t mapped_segment_size(void* segment_address)
{
    void* block_of_region_list = global_heap_info.first_region;
    while (block_of_region_list != NULL)
    {
        mapped_region__border_arr* dummy = (mapped_region__border_arr*)block_of_region_list; 
        size_t size = dummy->size;
        void** a1 = (void**)((char*)block_of_region_list + sizeof(mapped_region__border_arr));
        for (int i = 0; i < size; i += 2)
        {
            // zameniti ovu ukletu pointer aritmetiku sa [] radi citljivosti...
            if (*a1 == segment_address)
            {
                void** a2 = (void**)((char*)a1 + sizeof(void*));
                return (size_t)(*a2 - *a1);
            }
            a1 = (void**)((char*)a1 + (sizeof(void*) << 1));
        }
        block_of_region_list = dummy->next;
    }
    // ovde ne bi smeo da dodje
    return 0;
}


bool implemented = false;

// alloc_mem ce da zove kad nema vise memorije na heap-u
void* extend_heap(size_t alloc_size, void** start)
{
    void* mem;
    size_t heap_size;
    size_t total = alloc_size + sizeof(chunk);

    if (total < PAGE)
    {
        total = PAGE;
        mem = map_memory(PAGE);
    }
    else
    {
        total = ((total + PAGE - 1) / PAGE) * PAGE;

        //printf("OPA!\n");
        mem = map_memory(total);
    }
    if (global_heap_info.first_region == NULL)
       make_first_mapped_region(mem, total);
    else
       add_mapped_region(mem, total);

    //printf("Adresa: %p\n", mem);
    // sad se treba skrati prvi blok ako ima visak...
    size_t avail = total - sizeof(chunk);
    int leftover = total - alloc_size - (sizeof(chunk) << 1);
    //printf("leftover: %d\n", leftover);
    if (leftover > 0)
    {
        //printf("Ostalo: %ld\n", total - alloc_size - sizeof(chunk));
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
        //printf("NULL BURAZERU!!!\n");
        chunk* first = (chunk*)mem;  
        first->used = true;
        first->prev_size = 0;
        first->size = avail;
        first->next_free = NULL; // ne mora, pogledati...
        *start = (void*)((char*)mem + sizeof(chunk));
        // ovaj blok zauzima ceo mmap() prostor, pa sam po sebi ne moze da ima sledbenika niti ce moci da se coalescuje...
    }
}

void* alloc_mem(size_t size)
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
        if (leftover > sizeof(chunk)) // provera da li je moguce truncovati blok, p.s. ubaciti minimum_block_size da ne dobijam useless blokovi od par bajta
        {
            chunk* next_free = appropriate->next_free;
            appropriate->next_free = NULL; // ni ne mora al neka ga bmk...
            appropriate->used = true;
            appropriate->size = size;
            void* new_block_start = (char*)appropriate + sizeof(chunk) + size;
            bef->next_free = (chunk*)new_block_start;
            chunk* nb = (chunk*)new_block_start;
            nb->next_free = next_free;
            nb->size = leftover - sizeof(chunk);
            nb->used = false;
            nb->prev_size = size;
            global_heap_info.available -= (size + (sizeof(chunk)));
        }
        else
        {
            chunk* next_free = appropriate->next_free;
            appropriate->next_free = NULL;
            appropriate->used = true;
            //appropriate->size = size;
            bef->next_free = next_free;
            global_heap_info.available -= (size + leftover); // nema + sizeof(chunk) jer ga ceo zauzimamo i dolazi do unutrasnje fragmentacije
        }

    }
    else
    {
        size_t leftover = appropriate->size - size;
        if (leftover > sizeof(chunk)) // u buducnosti ce vrv biti 0 zamenjena sa MINIMUM_BLOCK_SIZE da ne dobijam blokove velicine svega nekoliko bajtova...
        {
            chunk* next_free = appropriate->next_free;
            appropriate->next_free = NULL;
            appropriate->used = true;
            appropriate->size = size;
            void* new_block_start = (char*)appropriate + sizeof(chunk) + size;
            global_heap_info.first_free_chunk = (chunk*)new_block_start;
            chunk* nb = (chunk*)new_block_start;
            void* nf = (void*)(nb->next_free);
            nb->next_free = next_free;
            nb->size = leftover - sizeof(chunk); // ovde sam bio stavio samo leftover i crko debagirajuci kad sam bilmez... 
            nb->used = false;
            nb->prev_size = size;
            global_heap_info.available -= (size + (sizeof(chunk)));
        }
        else
        {
            chunk* next_free = appropriate->next_free;
            appropriate->next_free = NULL;
            appropriate->used = true;
            //appropriate->size = size;
            global_heap_info.first_free_chunk = next_free;
            global_heap_info.available -= (size + leftover);
        }
    }
    //printf("Ostalo memorije na heap-u: %ld\n", global_heap_info.available);
    //print_free_blocks();
    void* ret_addr = (char*)appropriate + sizeof(chunk);
    return (void*)ret_addr;
}

void* alloc_mem_zero(size_t size)
{
    void* mem =  alloc_mem(size);
    if (mem)
    {
        char* mem_byte = (char*)mem;
        for (int i = 0; i < size; i++)
            mem_byte[i] = 0;
    }
        //memset(mem, 0, size); treba mi string.h za ovo, paralelno je i optimalnije, al yolo
    return mem;
}

chunk* find_free_predecessor(chunk* block)
{
    chunk* bef = NULL;
    chunk* current = global_heap_info.first_free_chunk;
    while(current)
    {
        if (current == block)
            return bef;
        bef = current;
        current = current->next_free;
    }
    //return NULL;
}

bool copy_mem_to_block(chunk* dest, chunk* src)
{   
    if (!dest || !src)
        return false;

    size_t to_copy = (src->size < dest->size) ? src->size : dest->size;

    char* src_byte = (char*)src + sizeof(chunk);
    char* dest_byte = (char*)dest + sizeof(chunk);
    for (int i = 0; i < src->size; i++)
        dest_byte[i] = src_byte[i];
    
    return true;
}

void free_mem(void* m)
{
    if (m == NULL)
        return;
    // chunk postaje free i dodaje se na vrh liste free blokova, posle odraditi coalescing sa prethodnim blokom...
    void* chunk_addr = (char*)m - sizeof(chunk);
    chunk* chunkk = (chunk*)chunk_addr;

    if (!chunkk->used)
        return;
    chunkk->used = false;

    // coalescing/spajanje sa prethodnim blokom ako je free...
    if (chunkk->prev_size > 0)
    {
        void* bef_chunk_addr = (char*)chunk_addr - chunkk->prev_size - sizeof(chunk);
        chunk* bef_chunk = (chunk*)bef_chunk_addr;
        // treba dodati i proveru da li je zadnji blok u delu mapirane memorije
        // mozda cu dodati u buducnosti i coalescing sa narednim blokom, ali nije neophodno...
        if (!bef_chunk->used)
        {
            bef_chunk->size += chunkk->size + sizeof(chunk);

            // prvi je, proveravamo velicinu, ako je ceo mapirani segment vracamo memoriju OS-u
            if (bef_chunk->prev_size == 0)
            {
                size_t mss = mapped_segment_size(bef_chunk_addr);
                if (bef_chunk->size == mss - sizeof(chunk))
                {
                    chunk* bef_free = find_free_predecessor(bef_chunk); 
                    if (bef_free)
                        bef_free->next_free = bef_chunk->next_free;
                    else
                        global_heap_info.first_free_chunk = bef_chunk->next_free; // NULL
                    unmap_memory(bef_chunk_addr, mss);
                    global_heap_info.available -= bef_chunk->size;
                    return;
                }
            }

            if (!chunk_is_last_in_region(chunkk))
            {
                chunk* next = (chunk*)((char*)bef_chunk + sizeof(chunk) + bef_chunk->size);
                next->prev_size = bef_chunk->size;
                global_heap_info.available += sizeof(chunk) + chunkk->size;  

                //printf("Ostalo memorije na heap-u: %ld\n", global_heap_info.available);
                //print_free_blocks();
                // blok iza je free sto znaci da je vec u free-listi pa odma return
                return;
            }
        }
    }
    size_t mss = mapped_segment_size(chunk_addr);
    if (chunkk->size == mss - sizeof(chunk))
    {
        chunk* bef_free = find_free_predecessor(chunkk);
        if (bef_free)
            bef_free->next_free = chunkk->next_free;
        else
            global_heap_info.first_free_chunk = chunkk->next_free; // NULL
        unmap_memory(chunk_addr, mss);
        global_heap_info.available -= chunkk->size;
        return;
    }
    global_heap_info.available += chunkk->size;
    chunkk->next_free = global_heap_info.first_free_chunk;
    global_heap_info.first_free_chunk = chunkk;
    //printf("Velicina: %ld\n", chunkk->size);
    //printf("Ostalo memorije na heap-u: %ld\n", global_heap_info.available);
    //print_free_blocks();
    return;
}

void* realloc_mem(void* mem, size_t new_size)
{
    if (mem == NULL)
        return NULL;
    
    if (new_size == 0)
    {
        free_mem(mem);
        return NULL;
    }

    void* chunk_addr = (char*)mem - sizeof(chunk);
    chunk* chunkk = (chunk*)chunk_addr;
    if (!chunk_is_last_in_region(chunkk))
    {
        void* next_chunk_addr = (void*)((char*)mem + chunkk->size);
        chunk* next_chunk = (chunk*)next_chunk_addr;

        if (!next_chunk->used && chunkk->size + next_chunk->size + sizeof(chunk) >= new_size && chunkk->size + next_chunk->size + sizeof(chunk) <= new_size << 1) 
        {
            chunk* bef_chunk = find_free_predecessor(chunkk);
            if (bef_chunk != NULL)
                bef_chunk->next_free = next_chunk->next_free;
            else
                global_heap_info.first_free_chunk = next_chunk->next_free;

            chunkk->size += next_chunk->size + sizeof(chunk);
            return mem;
        }
        else
        {
            void* new_mem = alloc_mem(new_size);
            if (!new_mem)
                return NULL;
            
            //memcpy(new_mem, mem, chunkk->size);
            copy_mem_to_block((chunk*)((char*)new_mem - sizeof(chunk)), chunkk);
            free_mem(mem);
            return new_mem;
        }
    }
    else
    {   // duplirano al nmvz...
        void* new_mem = alloc_mem(new_size);
        if (!new_mem)
            return NULL;

        copy_mem_to_block((chunk*)((char*)new_mem - sizeof(chunk)), chunkk);
        free_mem(mem);
        return new_mem;
    }
}

bool test1(int m, int n, int o)
{
    int** a = (int**)alloc_mem(sizeof(int*) * m);
    for (int i = 0; i < m; i++)
        a[i] = (int*)alloc_mem(sizeof(int) * n);
    
    int** b = (int**)alloc_mem(sizeof(int*) * n);
    for (int i = 0; i < n; i++)
        b[i] = (int*)alloc_mem(sizeof(int) * o);
    
    int k = 542;
    for (int i = 0; i < m; i++)
    {
        for (int j = 0; j < n; j++)
        {
            a[i][j] = (k + 12345) % 228;
            k = a[i][j];
        } 
    }

    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < o; j++)
        {
            b[i][j] = (k + 12345) % 228;
            k = b[i][j];
        } 
    }

    int** c = (int**)alloc_mem(sizeof(int*) * m);
    for (int i = 0; i < m; i++)
        c[i] = (int*)alloc_mem(sizeof(int) * o);

    for (int i = 0; i < m; i++)
        for (int j = 0; j < o; j++)
        {
            int s = 0;
            for (int k = 0; k < n; k++)
            {
                s += a[i][k] * b[k][j]; 
            }
            c[i][j] = s;
        }    

    for (int i = 0; i < m; i++)
    {
        for (int j = 0; j < o; j++);
            //printf("%d ", c[i][j]);
        //printf("\n");  
    }

    for (int i = 0; i < m; i++)
        free_mem(a[i]);
    free_mem(a);

    for (int i = 0; i < n; i++)
        free_mem(b[i]);
    free_mem(b);

    for (int i = 0; i < m; i++)
        free_mem(c[i]);
    free_mem(c);

    return true;
}

bool test2()
{
    void  *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k;

    a = alloc_mem(1000);
    b = alloc_mem(200);
    c = alloc_mem(53);
    d = alloc_mem(18);
    e = alloc_mem(37);
    f = alloc_mem(127);
    g = alloc_mem(127);
    h = alloc_mem(50);
    i = alloc_mem(32);

    j = alloc_mem(5000);
    k = alloc_mem(4000);

    free_mem(g);
    free_mem(c);
    free_mem(d);
    free_mem(e);

    free_mem(a);
    free_mem(b);
    free_mem(f);

    free_mem(h);
    free_mem(i);
    free_mem(j);
    free_mem(k);

    return true;    
}

bool test3()
{
    int* a = alloc_mem_zero(10000 * sizeof(int));
    for (int i = 0; i < 10000; i++);
        //printf("%d ", a[i]);
    return true;
}

int main(int argc, char** argv)
{
    
    //printf("void* velicina: %ld\n", sizeof(void*));
    //printf("%ld\n", sizeof(mapped_region__border_arr));
    
    test1(1000, 1000, 1000);
    test2();
    test3();
    
    //printf("POZDRAV!\n");
    return 0;               
}