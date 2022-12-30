#include <debug.h>
#include <info.h>
#include <asm.h>
#include <segmem.h>
#include <pagemem.h>
#include <intr.h>
#include <types.h>
#include <cr.h>

/*
** Segmentation selectors
*/
#define RING0_CODE  1
#define RING0_DATA  2
#define RING3_CODE  3
#define RING3_DATA  4
#define TSS  5

/*
** Kernel addresses
*/
#define KERNEL_PGD 0x100000
#define KERNEL_PTB 0x101000

/*
** User addresses
*/
#define SHARED_MEMORY 0x800000 
#define USER_KERNEL_STACK_START_OFFSET 0xffff0
#define USER_STACK_START_OFFSET 0xefff0
#define USER_PGD_OFFSET 0x20000
#define USER_PTB_OFFSET 0x21000
#define TSS_ADDR 0xd0000

#define GDT_SIZE 6
