#include "print.h"
#include "header.c"

//-- Print the cartography of the memory --//
void print_memory_cartography(idt_reg_t idtr, uint32_t increment_counter, uint32_t print_counter){
    get_idtr(idtr);int_desc_t *idt = idtr.desc;
    debug("|------------------------------------|\n");
    debug("|######    MEMORY CARTOGRAPHY   #####|\n");
    debug("|------------------------------------|\n");
    debug("|----  Kernel physical addresses  ----|\n");
    debug("|         PGD Kernel |  0x%x     |\n", KERNEL_PGD);
    debug("|         PTB Kernel |  0x%x     |\n", KERNEL_PTB);
    debug("|       Kernel stack |  0x%x      |\n", USER_KERNEL_STACK_START_OFFSET);
    debug("|                idt |  0x%x     |\n", idt);
    debug("|------------------------------------|\n");
    debug("|----   User physical addresses  ----|\n");
    debug("|Kernel stack task 1 |  0x%x     |\n", increment_counter + USER_KERNEL_STACK_START_OFFSET);
    debug("|Kernel stack task 2 |  0x%x     |\n", print_counter + USER_KERNEL_STACK_START_OFFSET);
    debug("|      Shared memory |  0x%x     |\n", SHARED_MEMORY);
    debug("|         PGD task 1 |  0x%x     |\n", increment_counter + USER_PGD_OFFSET);
    debug("|         PTB task 1 |  0x%x     |\n", increment_counter + USER_PTB_OFFSET);
    debug("|         PGD task 2 |  0x%x     |\n", print_counter + USER_PGD_OFFSET);
    debug("|         PTB task 2 |  0x%x     |\n", print_counter + USER_PGD_OFFSET);
    debug("|------------------------------------|\n\n");
}

//-- Print the detail when one task is added --//
void print_stack_tasks(uint32_t *user_kernel_esp, unsigned int number_tasks){
    debug("|------------------------------------|\n");
    debug("|########   Task %d is added   #######|\n", number_tasks);
    debug("|------------------------------------|\n");
    debug("|                 ss |  0x%x          |\n", *(user_kernel_esp));
    debug("|                esp |  0x%x         |\n", *(user_kernel_esp - 1));
    debug("|              flags |  0x%x     |\n", *(user_kernel_esp - 2));
    debug("|                 cs |  0x%x        |\n", *(user_kernel_esp - 3));
    debug("|                eip |  0x%x         |\n", *(user_kernel_esp - 4));
    debug("|         esp kernel |  0x%x     |\n", user_kernel_esp - 14);
    debug("|------------------------------------|\n\n");
}