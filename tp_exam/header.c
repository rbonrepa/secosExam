#include <debug.h>
#include <info.h>
#include <asm.h>
#include <segmem.h>
#include <pagemem.h>
#include <intr.h>
#include <cr.h>

#define GDT_SIZE 6 
//--- Segmentation selectors ---//
#define RING0_CODE  1
#define RING0_DATA  2
#define RING3_CODE  3
#define RING3_DATA  4
#define TSS  5

//--- Kernel addresses ---//
#define KERNEL_PGD 0x200000
#define KERNEL_PTB 0x210000

//--- User physical addresses ---//
#define SHARED_MEMORY 0x800000 
#define USER_KERNEL_STACK_START_OFFSET 0xffff0
#define USER_STACK_START_OFFSET 0xefff0

//--- User virtual addresses ---//
#define USER_PGD_OFFSET 0xc0000
#define USER_PTB_OFFSET 0xc1000
