#include "debug.h"
#include "mmu.h"
#include "string.h"
#include "common.h"

__attribute__((section(".text.main"))) void main(void) {
    // This payload is executed right before LK emits an event to notify
    // the system that it has to boot Linux.
    printf("Entered pre-notify_boot_linux() stage3 payload!\n");

    // If we wanted to, we could also patch the text in the rodata section by   
    // modifying the page table entries of the kernel address space.            
    //                                                                          
    // The following code demonstrates how to patch the "Orange State" string   
    // in the bootloader’s rodata section, which is used to indicate that the   
    // bootloader has been unlocked.                                            
    //                                                                          
    // In this case, it won't be noticeable since we're already patching the    
    // bootloader image to always use green state, but it serves as an example. 
    // set_pte_rwx(0xFFFF000050f9E3AE); // This modifies the page entry for the address
                                     // to allow read, write (and execute)
    // strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");

    // In this case we don't have to call any function since we're pivoting
    // from a printf() call, which isn't expected to return anything meaningful.
}