/* GPLv2 (c) Airbus */
#include "print.c"
#include "header.c"

//--- Global variables ---// 
seg_desc_t gdt[GDT_SIZE];
tss_t tss;
idt_reg_t idtr;
uint32_t tasks[4] = {};
unsigned int number_tasks = 0;
int current_task = -1;

//--- Define the userland ---//
__attribute__((section(".sys_count"))) void sys_counter(uint32_t*counter){
    asm volatile("int $80"::"S"(counter));
}

/* Task 1: counteur in shared memory. */
__attribute__((section(".user1"))) void increment_counter(){
    uint32_t *shared_mem = (uint32_t *)SHARED_MEMORY;
    *shared_mem = 0;
    while (1)
      (*shared_mem)++;
}

/* Task 2: print counteur in shared memory. */ 
__attribute__((section(".user2"))) void print_counter(){
    uint32_t *shared_mem = (uint32_t *)0x801000;
    while (1)
      sys_counter(shared_mem);
}

//--- Pagination ---//
/* This function creates one pgd and 2 ptb of 1024 entries. */
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
    // Enable paging 
    set_cr3(pgd);   
}

//--- Define kernel ---//
/* This function allows to initialise gdt, tss, registers, and pagination. */
void set_kernel(){
    // Initialisaion gdt
    gdt_reg_t gdtr = {
	desc : gdt,
	limit : sizeof(gdt) - 1
    };
	
    // Initialisation tss
    memset(&tss, 0, sizeof tss); // reserve memory
    //tss_dsc(&gdt[TSS], (offset_t)&tss); // record in the gdt
    set_gdtr(gdtr);
	
    // Initialisation registres in gdt
    /* En commentaire car fait bugguer mais important
    set_cs(gdt_krn_seg_sel(RING0_CODE)); 
    set_ss(gdt_krn_seg_sel(RING0_DATA));
    set_ds(gdt_krn_seg_sel(RING0_DATA));
    set_es(gdt_krn_seg_sel(RING0_DATA));
    set_fs(gdt_krn_seg_sel(RING0_DATA));
    set_gs(gdt_krn_seg_sel(RING0_DATA));*/
	
    // Activation of pagination for kenerl: set pgd at 0x310000, ptb at 0x311000
    set_mapping((pde32_t *)KERNEL_PGD, (pte32_t *)KERNEL_PTB, PG_KRN | PG_RW);
}

//--- Define tasks ---//
/* This function allows to create one task with pgd/ptb, kernel stack and add the task to the shared memory. */
void set_task(uint32_t user_task){
    // Create pgd/ptb
    pde32_t *pgd_task = (pde32_t *)(user_task + USER_PGD_OFFSET);
    pte32_t *ptb_task = (pte32_t *)(user_task + USER_PTB_OFFSET);
    set_mapping(pgd_task, ptb_task, PG_USR | PG_RW);

    // Set the kernel stack
    uint32_t *user_kernel_esp = (uint32_t *)(user_task + USER_KERNEL_STACK_START_OFFSET);
    *(user_kernel_esp - 1) = gdt_usr_seg_sel(RING3_DATA);   // SS
    *(user_kernel_esp - 2) = user_task + USER_STACK_START_OFFSET; // ESP
    *(user_kernel_esp - 3) = EFLAGS_IF;                           // Flags
    *(user_kernel_esp - 4) = gdt_usr_seg_sel(RING3_CODE);   // CS
    *(user_kernel_esp - 5) = user_task;                           // EIP

    print_stack_tasks(user_kernel_esp, number_tasks);

    // Create the shared memory
    pte32_t *ptb_shared = (pte32_t *)(user_task + USER_PTB_OFFSET + 2 * 4096);
    pg_set_entry(&pgd_task[2], PG_USR | PG_RW, page_nr(ptb_shared)); // pgd[0] = ptb1, pgd[1] = ptb2, pgd[2] = ptb_shared
    pg_set_entry(&ptb_shared[0], PG_USR | PG_RW, page_nr(SHARED_MEMORY)); // Pointe vers une même adresse

    number_tasks++;
}

//--- Kernel interruptions ---//
/* This function allows to change task (task1->task2 and reverse). */
void handler_scheduler(){
    debug("Scheduler");
    // They are no task 
    if (number_tasks <= 0)
        return;

    // It is the first time
    if (current_task == -1){
        current_task = 0;
        ///set_cr3(tasks[current_task_pid].PGD);
    }

    // Change task
    else{
        // Code to trint the counteur with kernel syscall
        debug("Change task");
        uint32_t task = tasks[current_task];
        current_task = (current_task + 1) % number_tasks;
        uint32_t user_kernel_esp = task + USER_KERNEL_STACK_START_OFFSET;
        // Record the context
        tss.s0.ss = gdt_krn_seg_sel(RING0_DATA);
        tss.s0.esp = user_kernel_esp;
        //Change context

        /* Changer de contexte
        //set_cr3(task + USER_PGD_OFFSET);
        int32_t esp = user_kernel_esp - (4 * 13); // 13 entries were pushed to the stack
        asm volatile(
        "mov %0, %%eax\n"
        :
        : "r"(esp));*/
    }
}

/* This function allows to print the task2 with a syscall. */
void handle_kernel_print(){
    // Code to trint the counteur with kernel syscall
    debug("Print counteur");
}

//--- Start tasks ---//
/* This function allows to create idtr and register the thow handlers below. */
void start_tasks(){
    // Set registers in user land
    /*
    set_ds(gdt_usr_seg_sel(RING3_DATA));
    set_es(gdt_usr_seg_sel(RING3_DATA));
    set_fs(gdt_usr_seg_sel(RING3_DATA));
    set_gs(gdt_usr_seg_sel(RING3_DATA));
    set_tr(gdt_krn_seg_sel(TSS));*/

    tss.s0.ss = gdt_krn_seg_sel(RING0_DATA);
    tss.s0.esp = get_esp();
	
    // Define idt
    idt_reg_t idtr;
    get_idtr(idtr);
    int_desc_t *idt = idtr.desc; //tableau comportant au maximum 256 descripteurs de 8 octets chacun, soit un descripteur par interruption. 

    // Record handler for counter and schedule in idt.
    int_desc(&idt[32], gdt_krn_seg_sel(RING0_CODE), (offset_t)handler_scheduler);
    idt[32].dpl = SEG_SEL_USR;

    // Record handler for syscall and print in idt.
    int_desc(&idt[0x80], gdt_krn_seg_sel(RING0_CODE), (offset_t)handle_kernel_print);
    idt[0x80].dpl = SEG_SEL_USR; 

    // Start
    //asm volatile("int $0x80;\n");  
}

void tp(){
    debug("|------   Work demonstration   ------|\n");
    print_memory_cartography(idtr, (uint32_t)increment_counter, (uint32_t)print_counter);

    // Set up kernel: init gdt, tss, register and pagination
    set_kernel();
    
    // Set up 2 tasks: init pagination, kernel stack and shared memory
    //set_cr0(get_cr0() | CR0_PG | CR0_PE);
    set_task((uint32_t)increment_counter);
    set_task((uint32_t)print_counter);
    	
    // Start task: init idt and records handlers
    start_tasks();    
    
    debug("|------------     Fin     -----------|\n");

    while(1);
}
