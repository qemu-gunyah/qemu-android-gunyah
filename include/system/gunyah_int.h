/*
 * QEMU Gunyah hypervisor support
 *
 * Copyright(c) 2023 Qualcomm Innovation Center, Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* header to be included in Gunyah-specific code */

#ifndef GUNYAH_INT_H
#define GUNYAH_INT_H

#include "qemu/accel.h"
#include "qemu/typedefs.h"
#include "qemu/thread.h"

typedef struct gunyah_slot {
    uint64_t start;
    uint64_t size;
    uint8_t *mem;
    uint32_t id;
    uint32_t flags;

    /*
     * @lend indicates if memory was lent.
     *
     * This flag is temporarily used until the upstream Gunyah kernel driver
     * patches are updated to support indication of lend vs share via flags
     * field of GH_SET_USER_MEM_API interface.
     */
    bool lend;
} gunyah_slot;

#define GUNYAH_MAX_MEM_SLOTS    32

struct GUNYAHState {
    AccelState parent_obj;

    QemuMutex slots_lock;
    gunyah_slot slots[GUNYAH_MAX_MEM_SLOTS];
    uint32_t nr_slots;
    int fd;
    int vmfd;
    uint64_t swiotlb_size;
    bool preshmem_reserved;
    uint32_t preshmem_size;
    uint32_t nr_irqs;
    uint32_t vm_started;
    uint64_t dtb_start;     /* Guest physical address of DTB */
    uint64_t dtb_size;      /* Size of DTB region (for SET_DTB_CONFIG) */

    /*
     * Protected VM mode: memory is lent to the guest via
     * GH_VM_ANDROID_LEND_USER_MEM instead of shared via
     * GH_VM_SET_USER_MEM_REGION. Required on devices that
     * only support protected VMs (equivalent to crosvm's
     * --protected-vm-without-firmware).
     */
    bool protected_vm;

    /*
     * Kernel entry point set by the machine (virt.c) after arm_load_kernel().
     * Includes the text_offset from the ARM64 Image header.
     * 0 means not set (fall back to scanning memory for ARM64 magic).
     */
    uint64_t kernel_entry;
};

struct AccelCPUState {
    int fd;
    struct gh_vcpu_run *run;

    /* Per-CPU page fault tracking (avoids cross-thread interference) */
    uint64_t last_fault_addr;
    int same_fault_count;
};

int gunyah_create_vm(void);
void gunyah_start_vm(void);
int gunyah_vm_ioctl(int type, ...);
void *gunyah_cpu_thread_fn(void *arg);
int gunyah_add_irqfd(int irqfd, int label, Error **errp);
GUNYAHState *get_gunyah_state(void);
int gunyah_arch_put_registers(CPUState *cs, int level);
void gunyah_cpu_synchronize_post_reset(CPUState *cpu);
gunyah_slot *gunyah_find_slot_by_addr(uint64_t addr);

#endif    /* GUNYAH_INT_H */
