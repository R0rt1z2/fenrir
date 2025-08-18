#pragma once

#include "common.h"

struct list_node {
    struct list_node *prev;
    struct list_node *next;
};

typedef struct {
	uint64_t tt_phys;
	pte_t * tt_virt;
	uint64_t flags;
	uint64_t base;
	uint64_t size;
} arch_aspace_t;

typedef struct vmm_aspace {
    struct list_node node;
    char name[32];
    uint flags;
    vaddr_t base;
    size_t  size;
    struct list_node region_list;
    arch_aspace_t arch_aspace;
} vmm_aspace_t;

#define MMU_KERNEL_PAGE_TABLE_ENTRIES_TOP 0x200
#define MMU_KERNEL_TOP_SHIFT 39
#define MMU_KERNEL_SIZE_SHIFT 48
#define MMU_KERNEL_PAGE_SIZE_SHIFT 0xC

#define MMU_USER_PAGE_TABLE_ENTRIES_TOP MMU_KERNEL_PAGE_TABLE_ENTRIES_TOP
#define MMU_USER_TOP_SHIFT MMU_KERNEL_TOP_SHIFT
#define MMU_USER_PAGE_SIZE_SHIFT MMU_KERNEL_PAGE_SIZE_SHIFT

#define MMU_PTE_DESCRIPTOR_MASK 0x3
#define MMU_PTE_OUTPUT_ADDR_MASK 0xfffffffff000
#define MMU_PTE_DESCRIPTOR_INVALID 0x0
#define MMU_PTE_L012_DESCRIPTOR_TABLE 0x3

#define MMU_PTE_ATTR_RES_SOFTWARE               BM(55, 4, 0xf)
#define MMU_PTE_ATTR_UXN                        BM(54, 1, 1)
#define MMU_PTE_ATTR_PXN                        BM(53, 1, 1)
#define MMU_PTE_ATTR_CONTIGUOUS                 BM(52, 1, 1)
#define MMU_PTE_ATTR_GP                         BM(50, 1, 1)
#define MMU_PTE_ATTR_NON_GLOBAL                 BM(11, 1, 1)
#define MMU_PTE_ATTR_AF                         BM(10, 1, 1)

#define MMU_PTE_ATTR_SH_NON_SHAREABLE           BM(8, 2, 0)
#define MMU_PTE_ATTR_SH_OUTER_SHAREABLE         BM(8, 2, 2)
#define MMU_PTE_ATTR_SH_INNER_SHAREABLE         BM(8, 2, 3)

#define MMU_PTE_ATTR_AP_P_RW_U_NA               BM(6, 2, 0)
#define MMU_PTE_ATTR_AP_P_RW_U_RW               BM(6, 2, 1)
#define MMU_PTE_ATTR_AP_P_RO_U_NA               BM(6, 2, 2)
#define MMU_PTE_ATTR_AP_P_RO_U_RO               BM(6, 2, 3)
#define MMU_PTE_ATTR_AP_MASK                    BM(6, 2, 3)

#define MMU_PTE_ATTR_NON_SECURE                 BM(5, 1, 1)

#define MMU_PTE_ATTR_ATTR_INDEX(attrindex)      BM(2, 3, attrindex)
#define MMU_PTE_ATTR_ATTR_INDEX_MASK            MMU_PTE_ATTR_ATTR_INDEX(7)
#define MMU_PTE_ATTR_NORMAL_MEMORY  0x8

#define MMU_PTE_L012_DESCRIPTOR_BLOCK  0x1
#define MMU_PTE_L3_DESCRIPTOR_PAGE  0x3

#define MMU_PTE_KERNEL_DATA_FLAGS \
    (MMU_PTE_ATTR_UXN | \
     MMU_PTE_ATTR_PXN | \
     MMU_PTE_ATTR_AF | \
     MMU_PTE_ATTR_SH_INNER_SHAREABLE | \
     MMU_PTE_ATTR_NORMAL_MEMORY | \
     MMU_PTE_ATTR_AP_P_RW_U_NA)

#define ARCH_ASPACE_FLAG_KERNEL (1U<<0)

#define KERNEL_ASPACE_BASE 0xFFFF000000000000UL
#define MMU_ARM64_GLOBAL_ASID (~0U)

vmm_aspace_t *get_kernel_aspace(void);
void set_pte_rwx(vaddr_t vaddr);
pte_t *get_pte(arch_aspace_t *aspace, vaddr_t vaddr);