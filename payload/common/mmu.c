#include "mmu.h"
#include "device_config.h"
#include "debug.h"

void *paddr_to_kvaddr(paddr_t paddr) {
  return ((void *(*)(paddr_t))PADDR_TO_KVADDR_ADDR)(paddr);
}

static inline bool is_valid_vaddr(arch_aspace_t *aspace, vaddr_t vaddr) {
    return (vaddr >= aspace->base && vaddr <= aspace->base + aspace->size - 1);
}

pte_t * get_pte(arch_aspace_t *aspace, vaddr_t vaddr) {
    uint index;
    uint index_shift;
    uint page_size_shift;
    pte_t pte;
    pte_t *ppte;
    pte_t pte_addr;
    uint descriptor_type;
    pte_t *page_table;
    vaddr_t vaddr_rem;

#ifdef DEBUG
    video_printf("aspace %p, vaddr 0x%lx\n", aspace, vaddr);
#endif

    if (!is_valid_vaddr(aspace, vaddr))
        return 0;

    if (aspace->flags & ARCH_ASPACE_FLAG_KERNEL) {
        index_shift = MMU_KERNEL_TOP_SHIFT;
        page_size_shift = MMU_KERNEL_PAGE_SIZE_SHIFT;

        vaddr_t kernel_base = ~0UL << MMU_KERNEL_SIZE_SHIFT;
        vaddr_rem = vaddr - kernel_base;

        index = vaddr_rem >> index_shift;
    } else {
        index_shift = MMU_USER_TOP_SHIFT;
        page_size_shift = MMU_USER_PAGE_SIZE_SHIFT;

        vaddr_rem = vaddr;
        index = vaddr_rem >> index_shift;
    }

    page_table = aspace->tt_virt;

    while (true) {
        index = vaddr_rem >> index_shift;
        vaddr_rem -= (vaddr_t)index << index_shift;
        ppte = &page_table[index];
        pte = page_table[index];
        descriptor_type = pte & MMU_PTE_DESCRIPTOR_MASK;
        pte_addr = pte & MMU_PTE_OUTPUT_ADDR_MASK;

        if (descriptor_type == MMU_PTE_DESCRIPTOR_INVALID)
            return 0;

        if (descriptor_type == ((index_shift > page_size_shift) ?
                                MMU_PTE_L012_DESCRIPTOR_BLOCK :
                                MMU_PTE_L3_DESCRIPTOR_PAGE)) {
            break;
        }
        
        page_table = (pte_t*)paddr_to_kvaddr(pte_addr);
        index_shift -= page_size_shift - 3;
    }

#ifdef DEBUG
    video_printf("pte: %llp %llx ppte:%llp\n",&pte,pte,ppte);
#endif

    return ppte;
}

vmm_aspace_t* get_kernel_aspace(void) {
    return (vmm_aspace_t *)KERNEL_ASPACE_ADDR;
}

void set_pte_rwx(vaddr_t vaddr) {
    vmm_aspace_t *kernel_aspace = get_kernel_aspace();
    pte_t *pte_addr = get_pte(&kernel_aspace->arch_aspace, vaddr);

#ifdef DEBUG
    video_printf("pte: %llx\n", *pte_addr);
#endif

    *pte_addr = (*pte_addr & ~MMU_PTE_ATTR_AP_MASK) | MMU_PTE_ATTR_AP_P_RW_U_RW;
    *pte_addr &= ~(MMU_PTE_ATTR_PXN | MMU_PTE_ATTR_UXN);
    *pte_addr |= MMU_PTE_ATTR_NORMAL_MEMORY;

    ARM64_TLBI(vaae1is, vaddr >> 12);
    ISB;
    DSB;
}