#ifndef MEMALLOC_H
#define MEMALLOC_H

#ifdef _WIN32
    #include <windows.h>
    #include <stddef.h> 
    #include <stdbool.h>
#else
    #define _GNU_SOURCE
    #include <sys/mman.h>
    #include <stddef.h> 
    #include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
    #ifdef BUILD_DLL
        #define DLL_EXPORT __declspec(dllexport)
    #else
        #define DLL_EXPORT __declspec(dllimport)
    #endif
#else
    #define DLL_EXPORT
#endif

DLL_EXPORT void* alloc_mem(size_t size);
DLL_EXPORT void* alloc_mem_zero(size_t size);
DLL_EXPORT void* realloc_mem(void* ptr, size_t new_size);
DLL_EXPORT void  free_mem(void* ptr);

#ifdef __cplusplus
}
#endif

#endif