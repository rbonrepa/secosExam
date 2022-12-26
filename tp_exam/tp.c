/* GPLv2 (c) Airbus */
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
#define TSS_S0  5
//--- Kernel address ---//
#define KERNEL_PGD 0x310000
#define KERNEL_PTB 0x311000
//--- User ---//
#define USER_KERNEL_STACK_START 0xffff0
#define USER_PGD_OFFSET 0xc0000
#define USER_PTB_OFFSET 0xc1000
#define SHARED_MEMORY 0x800000 

//--- Global variables ---// 
seg_desc_t gdt[GDT_SIZE];
tss_t tss;
task_t     task_1;
task_t     task_2;
int current_task = -1;

//--- Define the userland ---//
/* Task 1: counteur in shared memory. */
__attribute__((section(".user1"))) void increment_counter(){
    uint32_t *counter = (uint32_t *)0x800000;
    *counter = 0;
    while (1)
      (*counter)++;
}

/* Task 2: print counteur in shared memory. */ 
__attribute__((section(".user2"))) void print_counter(){
    uint32_t *counter = (uint32_t *)0x801000;
    while (1)
      sys_counter(counter);
}

//--- Pagination ---//
/* This function creates one pgd and 2 ptb of 1024 entries. */
void set_pagination(pde32_t *pgd, pte32_t *first_ptb, unsigned int flags){
    // Define pgd
    memset(pgd, 0, PAGE_SIZE);

    // For two entries in pgd, define pde of 1024 entries: pgd[0] = ptb1 and pgd[1] = ptb2
    int ptb_number = 1;   
    for (int ptb_num = 0; ptb_num <= ptb_number; ptb_num++){
	pte32_t *ptb = first_ptb + pdb_num * 4096;

	// For each entries in ptb, define one pte
	for (int ptb_entry = 0; ptb_entry < 1024; ptb_entry++)
	    pg_set_entry(&ptb[ptb_entry], flags, ptb_entry + ptb_num * 1024);

	// Add the ptb to the pgd
	pg_set_entry(&pgd[ptb_num], flags, page_nr(pte));
    }

    // Enable paging 
    set_cr3(pgd);
    uint32_t cr0 = get_cr0();
    set_cr0(cr0|CR0_PG);
}

//--- Segmentation of memory ---//
/* This function allows to initialise the segmentation selector in the kernel. */
void set_segmentation(){
    // Initialisation gdt
    gdt_reg_t gdtr = {
	desc : gdt,
	limit : sizeof(gdt) - 1
    };
    set_gdtr(gdtr);

    // Défine registres
    set_cs(gdt_krn_seg_sel(RING0_CODE)); 
    set_ss(gdt_krn_seg_sel(RING0_DATA));
    set_ds(gdt_krn_seg_sel(RING0_DATA));
    set_es(gdt_krn_seg_sel(RING0_DATA));
    set_fs(gdt_krn_seg_sel(RING0_DATA));
    set_gs(gdt_krn_seg_sel(RING0_DATA));

    set_ds(gdt_usr_seg_sel(RING3_DATA));
    set_es(gdt_usr_seg_sel(RING3_DATA));
    set_fs(gdt_usr_seg_sel(RING3_DATA));
    set_gs(gdt_usr_seg_sel(RING3_DATA));
    set_tr(gdt_krn_seg_sel(TSS_S0));

    // Initialisation tss
    memset(&tss, 0, sizeof tss);
    tss_dsc(&gdt[TSS_S0], (offset_t)&tss);
    tss.s0.ss = gdt_krn_seg_sel(GDT_D0);
    tss.s0.esp = get_esp();
}

//--- Define tasks ---//
/* This function allows to create one task with pgd/ptb, kernel stack and add the task to the shared memory. */
void set_task(uint32_t user_task){
    // Create pgd/ptb
    pde32_t *pgd_task = (pde32_t *)(user_task + USER_PGD_OFFSET);
    pte32_t *ptb_task = (pte32_t *)(user_task + USER_PTB_OFFSET);
    set_pagination(pgd_task, ptb_task, PG_USR | PG_RW);

    // Create the kernel stack
    uint32_t *user_kernel_esp = (uint32_t *)(user_task + USER_KERNEL_STACK_START_OFFSET);

    // Create the shared memory
    pte32_t *ptb_shared = (pte32_t *)(user_task + USER_PTB_OFFSET + 2 * 4096);
    pg_set_entry(&pgd_task[2], PG_USR | PG_RW, page_nr(ptb_shared)); // pgd[0] = ptb1, pgd[1] = ptb2, pgd[2] = ptb_shared
    pg_set_entry(&ptb_shared[0], PG_USR | PG_RW, page_nr(SHARED_MEMORY)); // Pointe vers une même adresse
}

//--- Kernel interruptions ---//
/* This function allows to change task (task1->task2 and reverse). */
void handler_clock(){
    if (num_tasks <= 0)
    return;

    current_task = (current_task + 1) % num_tasks;
    uint32_t task = tasks[current_task];

    /*
    // Record the context 
    // Find value in the tss 
    uint32_t user_kernel_esp = task + USER_KERNEL_STACK_START_OFFSET;
    uint32_t esp = user_kernel_esp - (4 * 13);
    tss.s0.ss = gdt_krn_seg_sel(RING0_DATA_ENTRY);
    tss.s0.esp = user_kernel_esp;
    // Change stack (esp registre)
    set_cr3(task + USER_PGD_OFFSET);

    // Change task:
     Change segment descriptor in GDT with index in tr 
    asm volatile(
      "mov %0, %%eax\n"
      :
      : "r"(esp));*/

}

/* This function allows to print the task2 with a syscall. */
void handle_kernel_print(){
    asm volatile("pusha\n");
    uint32_t *ptr;
    asm volatile(
        "mov %%eax, %0\n"
        : "=r"(ptr));
    debug("Counter: %d\n", *ptr);
    asm volatile(
        "popa\n"
        "leave\n"
        "iret\n");
}

//-- Interruption table --//
/* This function allows to create idtr and register the thow handlers aboce. */
void set_idt(){
    // Create idtr: registre with memory emplacement
    idt_reg_t idtr;
    get_idtr(idtr);

    // Define idt
    int_desc_t *idt = idtr.desc; //tableau comportant au maximum 256 descripteurs de 8 octets chacun, soit un descripteur par interruption. 

    // Address for handle_clock: permite to change task.
    int_desc(&idt[32], gdt_krn_seg_sel(RING0_CODE_ENTRY), (offset_t)handle_clock);
    idt[32].dpl = SEG_SEL_USR;

    // Address for handle_kernel_print: interruption for syscall
    int_desc(&idt[0x80], gdt_krn_seg_sel(RING0_CODE_ENTRY), (offset_t)handle_kernel_print);
    idt[0x80].dpl = SEG_SEL_USR;   
 }

void tp(){
    // Activation of pagination for kenerl: set pgd at 0x310000, ptb at 0x311000
    set_pagination((pde32_t *)KERNEL_PGD, (pte32_t *)KERNEL_PTB, PG_KRN | PG_RW);

    // Set up segmentation in kernel 
    set_segmentation();

    // Set up 2 tasks (pagination + kernel stack + user stack)
    set_task((uint32_t)increment_counter);
    set_task((uint32_t)print_counter);

    // Activation of pagination for tasks (pgd/ptb + kernel stack + shared memory)
    set_shared_memory((uint32_t)increment_counter, 0);
    set_shared_memory((uint32_t)print_counter, 1);
	
    // Start task
    set_ds(gdt_usr_seg_sel(RING3_DATA));
    set_es(gdt_usr_seg_sel(RING3_DATA));
    set_fs(gdt_usr_seg_sel(RING3_DATA));
    set_gs(gdt_usr_seg_sel(RING3_DATA));
    set_tr(gdt_krn_seg_sel(TSS_ENTRY));
    tss.s0.ss = gdt_krn_seg_sel(RING0_DATA);
    tss.s0.esp = get_esp();
    set_idt()

    while(1);
}
