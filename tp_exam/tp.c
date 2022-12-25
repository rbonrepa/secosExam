/* GPLv2 (c) Airbus */
#include <debug.h>
#include <info.h>
#include <asm.h>
#include <segmem.h>
#include <pagemem.h>
#include <intr.h>
#include <cr.h>

/// Global variables ///
/* Define GDT */ 
__attribute__((aligned(8))) seg_desc_t gdt[GDT_LIMIT];
/* Define TSS */
__attribute__((aligned(8))) tss_t tss;
/* Segmentation selectors*/
#define GDT_C0  1
#define GDT_D0  2
#define GDT_C3  3
#define GDT_D3  4
#define TSS_S0  5
/* Kernel physical address */
#define KERNEL_PGD 0x200000
#define KERNEL_PTB KERNEL_PGD + 0x1000

/* User physical address */
#define USER_CODE_OFFSET 0x00000
#define SHARED_MEMORY 0x80000

/* User virtual address */
#define USER_PGD_OFFSET 0xc0000
#define USER_PTB_OFFSET 0xc1000

extern info_t *info;

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

/* Define the task for organise processus*/
unsigned int num_tasks = 2;
uint32_t tasks[1] = {};
int current_task = -1;

/// Pagination ///
/* We use identity mapping.
   The size of pages is 4KB.
   Physical adress is chosen (with first_pte)
   Virtual adress is different.
*/
void set_pagination(pde32_t *pgd, pte32_t *first_pte, unsigned int flags){
    // Défine pgd
    memset(pgd, 0, PAGE_SIZE);
    
    // Define one or many page tables (pde) (2 pde of 1024 entries here)
    int pde_number = 1;   
    for (int pde_num = 0; pde_num <= pde_number; pde_num++){
        // For each entry in pde, define pte (page adress of 4096)
        pte32_t *pte = first_pte + pde_num * 4096;
        for (int pte_entry = 0; pte_entry < 1024; pte_entry++)
            pg_set_entry(&pte[pte_entry], flags, pte_entry + pde_num * 1024);

        // Add the pte to the pgd
        pg_set_entry(&pgd[pde_number], flags, page_nr(pte));
    }

    // Enable paging 
    set_cr3(pgd);
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

    // Initialisation tss
    memset(&tss, 0, sizeof tss);
    tss_dsc(&gdt[TSS_S0], (offset_t)&tss);

}

/// Define tasks ///
/* - One task have own PGD/PTB
   - They share one memory zone (page size)
   - They have their kernel stack
   - They have their user stack */ 
void set_task(){
    Ici on doit prépare une mémoire de page et une pile
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

/* ?? */
void handler(){
    if (num_tasks <= 0)
    return;
    
}

/// Interruption table ///
void set_idt(){
    // Create idtr
    idt_reg_t idtr;
    get_idtr(idtr);
    int_desc_t *idt = idtr.desc;

    offset_t idt = idtr.addr;
    idt += sizeof(int_desc_t) * 3; 

}
void tp()
{
    // Activation of pagination 
    set_pagination((pde32_t *)KERNEL_PGD_ADDR, (pte32_t *)KERNEL_PTB_ADDR, PG_KRN | PG_RW);
    set_cr0(get_cr0() | CR0_PG | CR0_PE);

    // Set up one memory segment 
    set_segmentation();

    // Set up 2 tasks
    set_task((uint32_t)increment_counter);
    set_task((uint32_t)print_counter);
    
    // Set shared memory up
    {
    // 0x800000 to 0x800000
    pde32_t *pgd = (pde32_t *)(increment_counter + USER_PGD_OFFSET);
    pte32_t *ptb = (pte32_t *)(increment_counter + USER_PTB_OFFSET + 2 * 4096);
    pg_set_entry(&pgd[2], PG_USR | PG_RW, page_nr(ptb));
    pg_set_entry(&ptb[0], PG_USR | PG_RW, page_nr(SHARED_MEMORY));
    }
    {
    // 0x801000 to 0x800000
    pde32_t *pgd = (pde32_t *)(print_counter + USER_PGD_OFFSET);
    pte32_t *ptb = (pte32_t *)(print_counter + USER_PTB_OFFSET + 2 * 4096);
    pg_set_entry(&pgd[2], PG_USR | PG_RW, page_nr(ptb));
    pg_set_entry(&ptb[1], PG_USR | PG_RW, page_nr(SHARED_MEMORY));
    }
}
