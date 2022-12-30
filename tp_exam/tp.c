/* GPLv2 (c) Airbus */
#include "print.c"
#include "header.c"
 
/*
** Global variables
*/
seg_desc_t gdt[GDT_SIZE];
tss_t tss;
idt_reg_t idtr;
uint32_t tasks[4] = {};
unsigned int number_tasks = 0;
int current_task = -1;

/*
** Define the userland
*/
__attribute__((section(".sys_count"))) void sys_counter(uint32_t*counter){
    asm volatile("int $80"::"S"(counter));
}
 
/*
** Task 1: counteur in shared memory.
*/
__attribute__((section(".user1"))) void increment_counter(){
    uint32_t *shared_mem = (uint32_t *)0x800000;
    *shared_mem = 0;
    while (1)
      (*shared_mem)++;
}

/*
** Task 2: print counteur in shared memory.
*/ 
__attribute__((section(".user2"))) void print_counter(){
    uint32_t *shared_mem = (uint32_t *)0x801000;
    while (1)
      sys_counter(shared_mem);
}

/*
** Pagination
** This function creates one pgd and 2 ptb of 1024 entries.
*/
void set_mapping(pde32_t *pgd, pte32_t *first_ptb, unsigned int flags){
    // Define pgd
    memset(pgd, 0, PAGE_SIZE);

    // For two entries in pgd, define pde of 1024 entries: pgd[0] = ptb1 and pgd[1] = ptb2
    int ptb_number = 1;   
    for (int ptb_num = 0; ptb_num <= ptb_number; ptb_num++){
        pte32_t *ptb = first_ptb + ptb_num * 4096;

            // For each entries in ptb, define one pte
            for (int ptb_entry = 0; ptb_entry < 1024; ptb_entry++)
                pg_set_entry(&ptb[ptb_entry], flags, ptb_entry + ptb_num * 1024);

        // Add the ptb to the pgd
        pg_set_entry(&pgd[ptb_num], flags, page_nr(ptb));
    }
       
}

/*
** Initialisation of segment descriptor.
*/
void init_seg_desc(uint64_t limit, uint64_t base, uint64_t type, uint64_t dpl, uint64_t index){
    gdt_reg_t gdtr;
    get_gdtr(gdtr);
    
    gdt[index].raw = 0ULL;
    gdt[index].base_1 = base;
    gdt[index].base_2 = base >> 16;
    gdt[index].base_3 = base >> 24;
    gdt[index].limit_1 = limit;
    gdt[index].limit_2 = limit >> 16;
    gdt[index].type = type;
    gdt[index].dpl = dpl;
    // Define the tss segment descriptor
    if (type == SEG_DESC_SYS_TSS_AVL_32){ 
        gdt[index].s = 0; 
        gdt[index].p = 1;
        gdt[index].avl = 0;
        gdt[index].l = 0;
        gdt[index].d = 0;
        gdt[index].g = 0;
    }
    else {
        gdt[index].s = 1; 
        gdt[index].p = 1;
        gdt[index].avl = 0;
        gdt[index].l = 0;
        gdt[index].d = 1;
        gdt[index].g = 1;
    }
    gdtr.limit = gdtr.limit + sizeof(seg_desc_t);

    set_gdtr(gdtr);
}

/*
** Define kernel
** This function allows to initialise gdt, tss, registers, and pagination.
*/
void set_kernel(){
    // Initialisaion of gdt
    gdt_reg_t gdtr;
    gdtr.limit = 0;
    gdtr.desc = gdt;
    set_gdtr(gdtr);
    init_seg_desc(0,0,0,0, 0);
    init_seg_desc(0xfffff,0,SEG_DESC_CODE_XR,0, 1); 
    init_seg_desc(0xfffff,0,SEG_DESC_DATA_RW,0, 2);  
    init_seg_desc(0xfffff,0,SEG_DESC_CODE_XR,3, 3);  
    init_seg_desc(0xfffff,0,SEG_DESC_DATA_RW,3, 4); 

    // Record TSS in the gdt 
    init_seg_desc(0xfffff,0,SEG_DESC_SYS_TSS_AVL_32,3, 4);
	
    // Initialisation of registres in gdt
    set_cs(gdt_krn_seg_sel(RING0_CODE));
    set_ss(gdt_krn_seg_sel(RING0_DATA));
    set_ds(gdt_krn_seg_sel(RING0_DATA));
    set_es(gdt_krn_seg_sel(RING0_DATA));
    set_fs(gdt_krn_seg_sel(RING0_DATA));
    set_gs(gdt_krn_seg_sel(RING0_DATA));

    // Activation of pagination for kenerl
    set_mapping((pde32_t *)KERNEL_PGD, (pte32_t *)KERNEL_PTB, PG_KRN | PG_RW);
    // Enable paging 
    set_cr3(KERNEL_PGD);
}

/*
** Define tasks
** This function allows to create one task with pgd/ptb, kernel stack and add the task to the shared memory.
*/
void set_task(uint32_t user_task){
    // Create and record the task
    tasks[number_tasks] = user_task;
    number_tasks++;

    // Set the kernel stack
    uint32_t *user_kernel_esp = (uint32_t *)(user_task + USER_KERNEL_STACK_START_OFFSET);
    *(user_kernel_esp - 1) = gdt_usr_seg_sel(RING3_DATA);   // SS
    *(user_kernel_esp - 2) = user_task + USER_STACK_START_OFFSET; // ESP
    *(user_kernel_esp - 3) = EFLAGS_IF;                           // Flags
    *(user_kernel_esp - 4) = gdt_usr_seg_sel(RING3_CODE);   // CS
    *(user_kernel_esp - 5) = user_task;                           // EIP

    print_stack_tasks(user_kernel_esp, number_tasks);
    
    // Set pagination for the task
    pde32_t *pgd_task = (pde32_t *)(user_task + USER_PGD_OFFSET);
    pte32_t *ptb_task = (pte32_t *)(user_task + USER_PTB_OFFSET);
    set_mapping(pgd_task, ptb_task, PG_USR | PG_RW);

    // Create the shared memory
    pte32_t *ptb_shared = (pte32_t *)(user_task + USER_PTB_OFFSET + 2 * 4096);
    pg_set_entry(&pgd_task[2], PG_USR | PG_RW, page_nr(ptb_shared)); // pgd[0] = ptb1, pgd[1] = ptb2, pgd[2] = ptb_shared
    pg_set_entry(&ptb_shared[0], PG_USR | PG_RW, page_nr(SHARED_MEMORY)); // Pointe vers une même adresse
}

/*
** Kernel interruptions
** This function allows to save contexte.
*/
void scheduler(){
    debug("Record contexte.\n");
    asm("handler_scheduler:\n");
    // Record contexte of the task 
    asm("pusha\n");
    // Code of interruption
    asm("call change_task\n");
    // Restor register
    asm("popa\n");
    // Return traiter l’interruption 3/ Restaurer les registres (popa), 4/ Retourner là où on était (iret)
    //asm("iret\n");
    debug("Repeat..\n");
}
/*
** This function allows to change task (task1->task2 and reverse).
*/
void change_task(){
    debug("Change task.\n");
    
    // For task 1, increment counter
    debug("Task 1:\n    Increment the counter in the shared memory.\n    To do ...\n");

    // For task 2, Print counter with syscall
    asm volatile("int $0x80;\n");  
}
/*
** This function allows to print the task 2 with a syscall.
*/
void syscall(){
    debug("Syscall interruption (80): \n    Print the value of the counter in the sharred memory.\n    To do...\n");
}

/*
** This function allows to create idtr and register the thow handlers below.
** Then we strat the interruption at the index 32.
*/
void start_tasks(){
    // Define idt
    idt_reg_t idtr;
    get_idtr(idtr);
    int_desc_t *idt = idtr.desc; //tableau comportant au maximum 256 descripteurs de 8 octets chacun, soit un descripteur par interruption. 

    // Record handler for scheduler in idt.
    int_desc(&idt[32], gdt_krn_seg_sel(RING0_CODE), (offset_t)scheduler);
    idt[32].dpl = SEG_SEL_USR;

    // Record handler for syscall in idt.
    int_desc(&idt[0x80], gdt_krn_seg_sel(RING0_CODE), (offset_t)syscall);
    idt[0x80].dpl = SEG_SEL_USR; 

    // Start
    asm volatile("int $32;\n");  
}

void tp(){
    debug("|------   Work demonstration   ------|\n");
    print_memory_cartography(idtr, (uint32_t)increment_counter, (uint32_t)print_counter);

    // Set up kernel: init gdt, tss, register and pagination
    set_kernel();
    set_cr0(get_cr0() | CR0_PG | CR0_PE);

    // Set up 2 tasks: init pagination, kernel stack and shared memory
    set_task((uint32_t)increment_counter);
    set_task((uint32_t)print_counter);
    	
    // Start task: init idt and records handlers
    start_tasks();    
    
    debug("\n|------------     Fin     -----------|\n");

    while(1);
}
