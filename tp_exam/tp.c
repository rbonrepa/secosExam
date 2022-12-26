/* GPLv2 (c) Airbus */
#include <debug.h>
#include <info.h>
#include <asm.h>
#include <segmem.h>
#include <pagemem.h>
#include <intr.h>
#include <cr.h>

#define GDT_SIZE 6 
/* Segmentation selectors*/
#define GDT_C0  1
#define GDT_D0  2
#define GDT_C3  3
#define GDT_D3  4
#define TSS_S0  5

/* Kernel physical address */
#define KERNEL_PGD 0x310000
#define KERNEL_PTB 0x311000

/* User */
#define USER_KERNEL_STACK_START 0xffff0

#define USER_PGD_OFFSET 0xc0000
#define USER_PTB_OFFSET 0xc1000

#define SHARED_MEMORY 0x800000 

/// Global variables ///
/* Define gdt, tss */ 
seg_desc_t gdt[GDT_SIZE];
tss_t tss;
/* Define tasks */
task_t     kernel;
task_t     task_1;
task_t     task_2;
int current_task = -1;
/* Define pgd */
pde32_t*   pgd_kr   = (pde32_t*) PGD0_BADDR;
pde32_t*   pgd_task1 = (pde32_t*) PGD1_BADDR;
pde32_t*   pgd_task2 = (pde32_t*) PGD2_BADDR;

/// Define the userland ///
/* User 1 is the task 1 (counteur in shared memory)*/
__attribute__((section(".user1"))) void increment_counter()
{
  uint32_t *counter = (uint32_t *)0x800000;
  *counter = 0;
  while (1)
  {
    (*counter)++;
  }
}
/*  User 2 is the task 2 (print counteur in shared memory)*/ 
__attribute__((section(".user2"))) void print_counter()
{
  uint32_t *counter = (uint32_t *)0x801000;
  while (1)
  {
    sys_counter(counter);
  }
}

/// Pagination ///
/* This function creates 2 ptb of 1024 entries in one pgd
*/
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

/// Segmetation of memory ///  
void set_segmentation(){
    // Initialisation gdt
    gdt_reg_t gdtr = {
        desc : gdt,
        limit : sizeof(gdt) - 1
    };
    set_gdtr(gdtr);

    // Défine registres
	set_cs(gdt_krn_seg_sel(GDT_C0)); 
	set_ss(gdt_krn_seg_sel(GDT_D0));
	set_ds(gdt_krn_seg_sel(GDT_D0));
	set_es(gdt_krn_seg_sel(GDT_D0));
	set_fs(gdt_krn_seg_sel(GDT_D0));
	set_gs(gdt_krn_seg_sel(GDT_D0));

    set_ds(gdt_usr_seg_sel(GDT_D3));
    set_es(gdt_usr_seg_sel(GDT_D3));
    set_fs(gdt_usr_seg_sel(GDT_D3));
    set_gs(gdt_usr_seg_sel(GDT_D3));
    set_tr(gdt_krn_seg_sel(TSS_S0));
    
    // Initialisation tss
    memset(&tss, 0, sizeof tss);
    tss_dsc(&gdt[TSS_S0], (offset_t)&tss);
    tss.s0.ss = gdt_krn_seg_sel(GDT_D0);
    tss.s0.esp = get_esp();

}

/// Define tasks ///
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

/// Interruption ///
/* Pass task 1 to task 2 (and reverse)*/
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

/** Handles `int 0x80`, i.e. syscall interrupts. */
void handle_syscall()
{
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

/// Interruption table ///
void set_idt(){
    // Create idtr: registre with memory emplacement
    idt_reg_t idtr;
    get_idtr(idtr);

    // Define idt
    //tableau comportant au maximum 256 descripteurs de 8 octets chacun, soit un descripteur par interruption. 
    int_desc_t *idt = idtr.desc;

    // Address for handle clock: permite to change task.
    int_desc(&idt[32], gdt_krn_seg_sel(RING0_CODE_ENTRY), (offset_t)handle_clock);
    idt[32].dpl = SEG_SEL_USR;

    // Interruption for syscall
    int_desc(&idt[0x80], gdt_krn_seg_sel(RING0_CODE_ENTRY), (offset_t)handle_syscall);
    idt[0x80].dpl = SEG_SEL_USR;   

}
void tp()
{
    // Kernel is identity mapped
    set_pagination((pde32_t *)KERNEL_PGD, (pte32_t *)KERNEL_PTB, PG_KRN | PG_RW);
   
    // Set up one memory segment 
    set_segmentation();

    // Set up 2 tasks (pagination + kernel stack + user stack)
    set_task((uint32_t)increment_counter);
    set_task((uint32_t)print_counter);
    
    // Set tasks in the shared memory
    set_shared_memory((uint32_t)increment_counter, 0);
    set_shared_memory((uint32_t)print_counter, 1);

    while(1);
}
