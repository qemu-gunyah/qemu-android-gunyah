/*
 * QEMU Gunyah hypervisor support
 *
 * (based on KVM accelerator code structure)
 *
 * Copyright 2008 IBM Corporation
 *           2008 Red Hat, Inc.
 *
 * Copyright(c) 2023 Qualcomm Innovation Center, Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <signal.h>
#include <ucontext.h>
#include <dlfcn.h>
#include "qemu/osdep.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1
#endif

/* Ensure MADV_HUGEPAGE is available for THP support */
#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 14
#endif

#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE 23
#endif

#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif
#include "qemu/typedefs.h"
#include "qemu/units.h"
#include "hw/core/cpu.h"
#include "system/cpus.h"
#include "system/gunyah.h"
#include "system/gunyah_int.h"
#include "linux-headers/linux/gunyah.h"
#include "exec/memory.h"
#include "qemu/error-report.h"
#include "exec/address-spaces.h"
#include "hw/boards.h"
#include "qapi/error.h"
#include "qemu/event_notifier.h"
#include "qemu/main-loop.h"
#include "system/runstate.h"
#include "qemu/guest-random.h"

static void gunyah_region_add(MemoryListener *listener,
                           MemoryRegionSection *section);
static void gunyah_region_del(MemoryListener *listener,
                           MemoryRegionSection *section);
static void gunyah_mem_ioeventfd_add(MemoryListener *listener,
                                  MemoryRegionSection *section,
                                  bool match_data, uint64_t data,
                                  EventNotifier *e);
static void gunyah_mem_ioeventfd_del(MemoryListener *listener,
                                  MemoryRegionSection *section,
                                  bool match_data, uint64_t data,
                                  EventNotifier *e);

/* Keep this here until Linux kernel UAPI header file (gunyah.h) is updated */
enum gh_vm_exit_type {
    GH_RM_EXIT_TYPE_VM_EXIT = 0,
    GH_RM_EXIT_TYPE_PSCI_POWER_OFF = 1,
    GH_RM_EXIT_TYPE_PSCI_SYSTEM_RESET = 2,
    GH_RM_EXIT_TYPE_PSCI_SYSTEM_RESET2 = 3,
    GH_RM_EXIT_TYPE_WDT_BITE = 4,
    GH_RM_EXIT_TYPE_HYP_ERROR = 5,
    GH_RM_EXIT_TYPE_ASYNC_EXT_ABORT = 6,
    GH_RM_EXIT_TYPE_VM_FORCE_STOPPED = 7,
};

/*
 * SIGSEGV diagnostic handler to identify the faulting address.
 * If the fault address is in the LEND region, it means QEMU is trying
 * to access memory that was lent to the guest (and is no longer accessible
 * to the host after VM_START).
 */
static void gunyah_print_symbol(const char *label, uintptr_t addr)
{
    Dl_info info;
    if (addr && dladdr((void *)addr, &info) && info.dli_sname) {
        fprintf(stderr, "%s: 0x%llx = %s + 0x%lx [%s]\n",
                label, (unsigned long long)addr,
                info.dli_sname,
                (unsigned long)(addr - (uintptr_t)info.dli_saddr),
                info.dli_fname ? info.dli_fname : "?");
    } else if (addr && dladdr((void *)addr, &info)) {
        fprintf(stderr, "%s: 0x%llx = ??? (in %s, nearest: %s)\n",
                label, (unsigned long long)addr,
                info.dli_fname ? info.dli_fname : "?",
                info.dli_sname ? info.dli_sname : "unknown");
    } else {
        fprintf(stderr, "%s: 0x%llx (no symbol info)\n",
                label, (unsigned long long)addr);
    }
}

static void gunyah_sigsegv_handler(int sig, siginfo_t *si, void *ctx)
{
    GUNYAHState *s = NULL;
    ucontext_t *uc = (ucontext_t *)ctx;
    int i;

    fprintf(stderr, "\n=== GUNYAH SIGSEGV DIAGNOSTIC ===\n");
    fprintf(stderr, "Signal: %d (%s)\n", sig,
            sig == SIGSEGV ? "SIGSEGV" : sig == SIGBUS ? "SIGBUS" : "?");
    fprintf(stderr, "Faulting address: %p\n", si->si_addr);
    fprintf(stderr, "Code: %d (%s)\n", si->si_code,
            si->si_code == SEGV_MAPERR ? "SEGV_MAPERR (unmapped)" :
            si->si_code == SEGV_ACCERR ? "SEGV_ACCERR (permission)" :
            "unknown");
    fprintf(stderr, "Thread ID: %d\n", (int)syscall(SYS_gettid));

    /* Print CPU registers from signal context (aarch64) */
    if (uc) {
        uintptr_t pc = uc->uc_mcontext.pc;
        uintptr_t lr = uc->uc_mcontext.regs[30];  /* X30 = LR */
        uintptr_t fp = uc->uc_mcontext.regs[29];  /* X29 = FP */
        uintptr_t sp = uc->uc_mcontext.sp;

        fprintf(stderr, "\nRegisters:\n");
        fprintf(stderr, "  PC=0x%llx  SP=0x%llx\n",
                (unsigned long long)pc, (unsigned long long)sp);
        fprintf(stderr, "  FP=0x%llx  LR=0x%llx\n",
                (unsigned long long)fp, (unsigned long long)lr);

        /* Print X0-X28 to see what pointer was NULL */
        for (i = 0; i < 29; i++) {
            if (i % 4 == 0) fprintf(stderr, " ");
            fprintf(stderr, " X%d=0x%llx", i,
                    (unsigned long long)uc->uc_mcontext.regs[i]);
            if (i % 4 == 3) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");

        /* Symbol lookup for PC and LR */
        gunyah_print_symbol("PC", pc);
        gunyah_print_symbol("LR (caller)", lr);

        /* Walk frame pointers for backtrace */
        fprintf(stderr, "\nBacktrace (frame pointer walk):\n");
        uintptr_t *frame = (uintptr_t *)fp;
        for (i = 0; i < 20 && frame; i++) {
            uintptr_t ret_addr = frame[1]; /* return address */
            if (ret_addr == 0) break;
            gunyah_print_symbol("  frame", ret_addr);
            uintptr_t *next_frame = (uintptr_t *)frame[0];
            /* Sanity check: frame pointer should increase */
            if (next_frame <= frame) break;
            frame = next_frame;
        }
    }

    fprintf(stderr, "\nMemory slots:\n");
    /* Try to get GUNYAHState to check if fault is in LEND region */
    s = get_gunyah_state();
    if (s) {
        fprintf(stderr, "vm_started: %u\n", s->vm_started);
        for (i = 0; i < s->nr_slots; ++i) {
            if (s->slots[i].size == 0) continue;
            uint8_t *mem_start = s->slots[i].mem;
            uint8_t *mem_end = mem_start + s->slots[i].size;
            uint8_t *fault = (uint8_t *)si->si_addr;
            bool in_slot = (fault >= mem_start && fault < mem_end);
            fprintf(stderr, "  slot[%d]: hva=%p-%p gpa=0x%llx size=0x%llx lend=%d%s\n",
                    i, mem_start, mem_end,
                    (unsigned long long)s->slots[i].start,
                    (unsigned long long)s->slots[i].size,
                    s->slots[i].lend,
                    in_slot ? " *** FAULT IS HERE ***" : "");
        }
    }

    if (current_cpu) {
        fprintf(stderr, "current_cpu: index=%d, fd=%d, run=%p\n",
                current_cpu->cpu_index,
                current_cpu->accel ? current_cpu->accel->fd : -999,
                current_cpu->accel ? (void *)current_cpu->accel->run : NULL);
    } else {
        fprintf(stderr, "current_cpu: NULL (not a VCPU thread)\n");
    }

    fprintf(stderr, "=== END SIGSEGV DIAGNOSTIC ===\n");
    fflush(stderr);

    /* Re-raise to get default behavior (core dump / exit) */
    signal(sig, SIG_DFL);
    raise(sig);
}

static void gunyah_install_sigsegv_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = gunyah_sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    error_report("GH: installed SIGSEGV/SIGBUS diagnostic handler");
}

static int gunyah_ioctl(int type, ...)
{
    void *arg;
    va_list ap;
    GUNYAHState *s = GUNYAH_STATE(current_accel());

    assert(s->fd);

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    return ioctl(s->fd, type, arg);
}

int gunyah_vm_ioctl(int type, ...)
{
    void *arg;
    va_list ap;
    GUNYAHState *s = GUNYAH_STATE(current_accel());

    assert(s->vmfd);

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    return ioctl(s->vmfd, type, arg);
}

static int gunyah_vcpu_ioctl(CPUState *cpu, int type, ...)
{
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    return ioctl(cpu->accel->fd, type, arg);
}

/*
 * Hex-dump a struct for ioctl debugging. Prints every byte so we can
 * compare QEMU's values against CrosVM's.
 */
static void ghdbg_hexdump(const char *label, const void *data, size_t len)
{
    const uint8_t *p = data;
    size_t i;
    char line[128];
    int pos = 0;

    error_report("GH-DBG: %s (%zu bytes):", label, len);
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) {
            if (i > 0) {
                error_report("GH-DBG:   %s", line);
            }
            pos = 0;
        }
        pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", p[i]);
    }
    if (pos > 0) {
        error_report("GH-DBG:   %s", line);
    }
}

static MemoryListener gunyah_memory_listener = {
    .name = "gunyah",
    .priority = MEMORY_LISTENER_PRIORITY_ACCEL,
    .region_add = gunyah_region_add,
    .region_del = gunyah_region_del,
    /*
     * Gunyah: ioeventfd disabled — the kernel driver on many Gunyah
     * platforms doesn't support GH_FN_IOEVENTFD and the ioctl triggers
     * SIGBUS instead of returning an error.  Virtio still works via
     * the MMIO exit path (slightly slower but fully functional).
     */
};

int gunyah_create_vm(void)
{
    GUNYAHState *s;
    int i;

    s = GUNYAH_STATE(current_accel());

    s->fd = qemu_open_old("/dev/gunyah", O_RDWR);
    if (s->fd == -1) {
        error_report("Could not access Gunyah kernel module at /dev/gunyah: %s",
                                strerror(errno));
        exit(1);
    }
    error_report("GH: /dev/gunyah opened, fd=%d", s->fd);

    s->vmfd = gunyah_ioctl(GH_CREATE_VM, 0);
    if (s->vmfd < 0) {
        error_report("Could not create VM: %s (errno=%d)", strerror(errno), errno);
        exit(1);
    }
    error_report("GH: VM created, vmfd=%d", s->vmfd);

    qemu_mutex_init(&s->slots_lock);
    s->nr_slots = GUNYAH_MAX_MEM_SLOTS;
    for (i = 0; i < s->nr_slots; ++i) {
        s->slots[i].start = 0;
        s->slots[i].size = 0;
        s->slots[i].id = i;
    }

    gunyah_install_sigsegv_handler();

    memory_listener_register(&gunyah_memory_listener, &address_space_memory);
    return 0;
}

#define gunyah_slots_lock(s)    qemu_mutex_lock(&s->slots_lock)
#define gunyah_slots_unlock(s)  qemu_mutex_unlock(&s->slots_lock)

static gunyah_slot *gunyah_find_overlap_slot(GUNYAHState *s,
                uint64_t start, uint64_t size)
{
    gunyah_slot *slot;
    int i;

    for (i = 0; i < s->nr_slots; ++i) {
        slot = &s->slots[i];
        if (slot->size && start < (slot->start + slot->size) &&
            (start + size) > slot->start) {
            return slot;
        }
    }

    return NULL;
}

gunyah_slot *gunyah_find_slot_by_addr(uint64_t addr)
{
    GUNYAHState *s = GUNYAH_STATE(current_accel());
    int i;
    gunyah_slot *slot = NULL;

    gunyah_slots_lock(s);
    for (i = 0; i < s->nr_slots; ++i) {
        slot = &s->slots[i];
        if (slot->size &&
            (addr >= slot->start && addr <= slot->start + slot->size))
                break;
    }
    gunyah_slots_unlock(s);

    return slot;
}

/* Called with s->slots_lock held */
static gunyah_slot *gunyah_get_free_slot(GUNYAHState *s)
{
    int i;

    for (i = 0; i < s->nr_slots; i++) {
        if (s->slots[i].size == 0) {
            return &s->slots[i];
        }
    }

    return NULL;
}

/*
 * Size of each LEND chunk.  The kernel's gunyah_gup_share_parcel() does
 * kcalloc(nr_pages, 8, GFP_KERNEL) to pin pages during bulk LEND.
 * For a single 8GB region that's a 16MB contiguous allocation — too large
 * for a phone's fragmented kernel memory.
 *
 * By splitting into 256MB chunks, each kcalloc is only 512KB (easily
 * allocable), and the gh_bulk_lend KPM can successfully bulk-LEND each
 * chunk via the Resource Manager.
 */
#define GUNYAH_LEND_CHUNK_SIZE  (256ULL * 1024 * 1024)  /* 256 MB */

/*
 * Register one memory slot + ioctl with the kernel.
 * Caller is responsible for pre-faulting; this just does the slot + ioctl.
 */
static void gunyah_add_mem_slot(GUNYAHState *s,
        uint8_t *hva, uint64_t gpa, uint64_t size,
        bool lend, enum gh_mem_flags flags)
{
    gunyah_slot *slot;
    struct gh_userspace_memory_region gumr;
    int ret;

    slot = gunyah_get_free_slot(s);
    if (!slot) {
        error_report("No free slots to add memory!");
        exit(1);
    }

    slot->size = size;
    slot->mem = hva;
    slot->start = gpa;
    slot->lend = lend;

    gumr.label = slot->id;
    gumr.flags = flags;
    gumr.guest_phys_addr = gpa;
    gumr.memory_size = size;
    gumr.userspace_addr = (__u64) hva;

    error_report("GH: add_mem label=%u gpa=0x%"PRIx64" size=0x%"PRIx64
                 " hva=0x%"PRIx64" flags=0x%x lend=%d",
                 gumr.label, (uint64_t)gumr.guest_phys_addr,
                 (uint64_t)gumr.memory_size, (uint64_t)gumr.userspace_addr,
                 gumr.flags, lend);

    if (lend) {
        ret = gunyah_vm_ioctl(GH_VM_ANDROID_LEND_USER_MEM, &gumr);
    } else {
        ret = gunyah_vm_ioctl(GH_VM_SET_USER_MEM_REGION, &gumr);
    }

    if (ret) {
        error_report("GH: %s ioctl FAILED: %s (ret=%d, errno=%d)",
                     lend ? "LEND" : "SHARE", strerror(errno), ret, errno);
        exit(1);
    }
    error_report("GH: add_mem_slot OK (gpa=0x%"PRIx64" size=0x%"PRIx64")",
                 gpa, size);
}

static void gunyah_add_mem(GUNYAHState *s, MemoryRegionSection *section,
        bool lend, enum gh_mem_flags flags)
{
    MemoryRegion *area = section->mr;
    uint64_t total_size = int128_get64(section->size);
    uint8_t *base_hva = memory_region_get_ram_ptr(area) +
                        section->offset_within_region;
    uint64_t base_gpa = section->offset_within_address_space;
    int ret;

    /*
     * Pre-fault all pages before LEND ioctl.
     *
     * The kernel's gunyah_gup_share_parcel() uses pin_user_pages_fast()
     * to pin pages during VM_START and bulk-LEND them to the hypervisor
     * via the Resource Manager (efficient large-page mappings).
     *
     * By touching every page now (MADV_POPULATE_WRITE), we ensure
     * all pages are physically resident when pin_user_pages runs,
     * so the bulk LEND includes everything.
     */
    if (lend) {
        FILE *f;
        const uint64_t thp_size = 2ULL * 1024 * 1024; /* 2MB */

        error_report("GH: preparing LEND region: hva=0x%"PRIx64
                     " size=0x%"PRIx64" (%"PRIu64" MB)",
                     (uint64_t)(uintptr_t)base_hva, total_size,
                     total_size >> 20);

        /*
         * THP strategy: each 2MB THP uses ONE hypervisor page table
         * entry instead of 512 × 4KB entries.  Without THPs, an 8GB
         * guest needs ~2M entries and exhausts the hypervisor's
         * fixed-size page table pool (ENOMEM crash).
         *
         * We do NOT cap total_size — capping creates a gap between
         * the LEND and SHARE regions that breaks the UEFI IoMmu driver.
         * Instead we allocate best-effort THPs (~90%+ coverage) which
         * is sufficient to avoid ENOMEM.  The gh_disable_deferred_split
         * KPM must be loaded to prevent kernel panics from kswapd
         * touching LEND'd THP pages.
         *
         * Phase 1: Free page cache + compact.
         * Phase 2: Populate in batches with MADV_HUGEPAGE.
         * Phase 3: MADV_COLLAPSE remaining 4KB pages (best-effort).
         * Phase 4: mlock everything.
         */

        /* Phase 1: Free memory and compact */
        error_report("GH: Phase 1: dropping caches + compacting ...");
        f = fopen("/proc/sys/vm/drop_caches", "w");
        if (f) { fprintf(f, "3\n"); fclose(f); }
        f = fopen("/proc/sys/vm/compact_memory", "w");
        if (f) { fprintf(f, "1\n"); fclose(f); }
        usleep(500000);

        /* Log available huge pages before allocation */
        {
            char line[256];
            f = fopen("/proc/meminfo", "r");
            if (f) {
                while (fgets(line, sizeof(line), f)) {
                    if (strstr(line, "AnonHugePages") ||
                        strstr(line, "MemFree") ||
                        strstr(line, "MemAvailable")) {
                        /* Remove trailing newline */
                        char *nl = strchr(line, '\n');
                        if (nl) *nl = '\0';
                        error_report("GH:   %s", line);
                    }
                }
                fclose(f);
            }
        }

        /* Request THPs for the whole region */
        ret = madvise(base_hva, total_size, MADV_HUGEPAGE);
        error_report("GH: MADV_HUGEPAGE: %s",
                     ret == 0 ? "OK" : strerror(errno));

        /* Diagnostic: check VMA flags for this region */
        {
            char smaps_path[64];
            char line[512];
            unsigned long target = (unsigned long)base_hva;
            snprintf(smaps_path, sizeof(smaps_path),
                     "/proc/%d/smaps", getpid());
            f = fopen(smaps_path, "r");
            if (f) {
                int in_our_vma = 0;
                while (fgets(line, sizeof(line), f)) {
                    /* VMA header line: "start-end perms ..." */
                    if (line[0] != ' ' && strchr(line, '-')) {
                        unsigned long vma_start = 0;
                        sscanf(line, "%lx-", &vma_start);
                        in_our_vma = (vma_start == target);
                        if (in_our_vma) {
                            char *nl = strchr(line, '\n');
                            if (nl) *nl = '\0';
                            error_report("GH: VMA: %s", line);
                        }
                    }
                    if (in_our_vma) {
                        if (strstr(line, "AnonHugePages") ||
                            strstr(line, "THPeligible") ||
                            strstr(line, "VmFlags")) {
                            char *nl = strchr(line, '\n');
                            if (nl) *nl = '\0';
                            error_report("GH:   %s", line);
                        }
                    }
                }
                fclose(f);
            }
        }

        /*
         * Phase 2: Populate in 256MB batches.
         *
         * Doing one huge MADV_POPULATE_WRITE exhausts free 2MB regions
         * early, and the rest falls back to 4KB.  By batching with
         * compaction between batches, we give the kernel a chance to
         * defragment the just-allocated 4KB pages and create new
         * 2MB regions for the next batch.
         */
        {
            const uint64_t batch_size = 256ULL * 1024 * 1024; /* 256MB */
            uint64_t offset;
            int batch_idx = 0;

            error_report("GH: Phase 2: populating %"PRIu64" MB in "
                         "%"PRIu64" x %"PRIu64" MB batches ...",
                         total_size >> 20,
                         (total_size + batch_size - 1) / batch_size,
                         batch_size >> 20);

            for (offset = 0; offset < total_size; offset += batch_size) {
                uint64_t len = total_size - offset;
                if (len > batch_size)
                    len = batch_size;

                ret = madvise((char *)base_hva + offset, len,
                              MADV_POPULATE_WRITE);
                if (ret != 0) {
                    /* Fallback: manual page touch for this batch */
                    volatile char *p = (volatile char *)base_hva + offset;
                    uint64_t npages = len / 4096;
                    uint64_t i;
                    for (i = 0; i < npages; i++) {
                        p[i * 4096] = p[i * 4096];
                    }
                }
                batch_idx++;

                /*
                 * Every 4 batches (1GB), compact memory.
                 * This lets the kernel merge fragmented 4KB regions
                 * into 2MB blocks for subsequent THP allocations.
                 */
                if (batch_idx % 4 == 0 && offset + batch_size < total_size) {
                    f = fopen("/proc/sys/vm/compact_memory", "w");
                    if (f) { fprintf(f, "1\n"); fclose(f); }
                    usleep(200000); /* 200ms for compaction */
                }
            }
            error_report("GH: Phase 2: population complete");
        }

        /* Log THP status after population */
        {
            char line[256];
            f = fopen("/proc/meminfo", "r");
            if (f) {
                while (fgets(line, sizeof(line), f)) {
                    if (strstr(line, "AnonHugePages")) {
                        char *nl = strchr(line, '\n');
                        if (nl) *nl = '\0';
                        error_report("GH:   after populate: %s", line);
                    }
                }
                fclose(f);
            }
        }

        /*
         * Phase 3: MADV_COLLAPSE + retry loop.
         *
         * First pass: try MADV_COLLAPSE on every 2MB chunk.
         * For chunks that fail: release their 4KB pages (MADV_DONTNEED),
         * compact memory, then re-populate and retry.  Releasing the
         * scattered 4KB pages lets compaction merge them into contiguous
         * 2MB blocks for the next THP allocation attempt.
         *
         * Repeat up to 5 times to push toward 100% THP coverage.
         */
        {
            uint64_t total_chunks = total_size / thp_size;
            uint64_t collapsed = 0, failed = 0;
            uint64_t chunk;
            int pass;
            int last_err = 0;

            /* Bitmap: 1 = needs THP, 0 = already THP */
            uint8_t *need_thp = (uint8_t *)calloc(total_chunks, 1);
            if (!need_thp) {
                error_report("GH: Phase 3: calloc failed, skipping");
                goto skip_phase3;
            }

            /* First pass: identify which chunks need collapsing */
            error_report("GH: Phase 3: MADV_COLLAPSE pass 0 ...");
            for (chunk = 0; chunk < total_chunks; chunk++) {
                ret = madvise((char *)base_hva + chunk * thp_size,
                              thp_size, MADV_COLLAPSE);
                if (ret == 0) {
                    collapsed++;
                } else {
                    need_thp[chunk] = 1;
                    failed++;
                    last_err = errno;
                }
            }
            error_report("GH:   pass 0: %"PRIu64" OK, %"PRIu64
                         " failed (err=%d), %.1f%%",
                         collapsed, failed, last_err,
                         (double)collapsed * 100.0 /
                         (double)total_chunks);

            /* Retry loop: release failed chunks, compact, re-populate */
            for (pass = 1; pass <= 5 && failed > 0; pass++) {
                uint64_t pass_ok = 0, pass_fail = 0;

                /* Release 4KB pages from failed chunks */
                for (chunk = 0; chunk < total_chunks; chunk++) {
                    if (need_thp[chunk]) {
                        madvise((char *)base_hva + chunk * thp_size,
                                thp_size, MADV_DONTNEED);
                    }
                }

                /* Compact memory — freed 4KB pages can now be merged */
                f = fopen("/proc/sys/vm/compact_memory", "w");
                if (f) { fprintf(f, "1\n"); fclose(f); }
                usleep(300000); /* 300ms for compaction */

                /* Re-populate and try MADV_COLLAPSE again */
                for (chunk = 0; chunk < total_chunks; chunk++) {
                    if (!need_thp[chunk])
                        continue;

                    /* Re-fault the pages (kernel will try THP first) */
                    madvise((char *)base_hva + chunk * thp_size,
                            thp_size, MADV_POPULATE_WRITE);

                    ret = madvise((char *)base_hva + chunk * thp_size,
                                  thp_size, MADV_COLLAPSE);
                    if (ret == 0) {
                        need_thp[chunk] = 0;
                        pass_ok++;
                    } else {
                        pass_fail++;
                        last_err = errno;
                    }
                }

                collapsed += pass_ok;
                failed = pass_fail;
                error_report("GH:   pass %d: +%"PRIu64" OK, "
                             "%"PRIu64" remaining, %.1f%%",
                             pass, pass_ok, failed,
                             (double)collapsed * 100.0 /
                             (double)total_chunks);

                /* If no progress, stop retrying */
                if (pass_ok == 0)
                    break;
            }

            error_report("GH: Phase 3 done: %"PRIu64"/%"PRIu64
                         " THPs (%.1f%%), %"PRIu64" stuck at 4KB",
                         collapsed, total_chunks,
                         (double)collapsed * 100.0 /
                         (double)total_chunks,
                         failed);

            /* Phase 3b trimming removed — size is capped upfront in Phase 0 */
            free(need_thp);
        }
skip_phase3:

        /* Final THP count */
        {
            char line[256];
            f = fopen("/proc/meminfo", "r");
            if (f) {
                while (fgets(line, sizeof(line), f)) {
                    if (strstr(line, "AnonHugePages")) {
                        char *nl = strchr(line, '\n');
                        if (nl) *nl = '\0';
                        error_report("GH:   final: %s", line);
                    }
                }
                fclose(f);
            }
        }

        /* Phase 4: Lock pages */
        ret = mlock(base_hva, total_size);
        if (ret == 0) {
            error_report("GH: mlock: OK");
        } else {
            error_report("GH: mlock FAILED: %s", strerror(errno));
        }
    }

    /*
     * Split large LEND regions into 256MB chunks.
     *
     * The kernel's gunyah_gup_share_parcel() calls kcalloc() to allocate
     * a page-pointer array for the entire region.  For 8GB that's 16MB
     * of contiguous kernel memory, which always fails on a phone.
     *
     * By splitting into 256MB chunks, each kcalloc is only 512KB.
     * The gh_bulk_lend KPM module calls gunyah_share_range_as_parcels()
     * per binding, and each binding is now small enough to succeed.
     */
    if (lend && total_size > GUNYAH_LEND_CHUNK_SIZE) {
        uint64_t offset = 0;
        int chunk_idx = 0;

        error_report("GH: splitting %"PRIu64" MB LEND into %"PRIu64
                     " x %"PRIu64" MB chunks",
                     total_size >> 20,
                     (total_size + GUNYAH_LEND_CHUNK_SIZE - 1) /
                         GUNYAH_LEND_CHUNK_SIZE,
                     GUNYAH_LEND_CHUNK_SIZE >> 20);

        while (offset < total_size) {
            uint64_t chunk_sz = total_size - offset;
            if (chunk_sz > GUNYAH_LEND_CHUNK_SIZE)
                chunk_sz = GUNYAH_LEND_CHUNK_SIZE;

            error_report("GH:   chunk[%d] gpa=0x%"PRIx64" size=0x%"PRIx64,
                         chunk_idx, base_gpa + offset, chunk_sz);
            gunyah_add_mem_slot(s, base_hva + offset,
                                base_gpa + offset, chunk_sz,
                                lend, flags);
            offset += chunk_sz;
            chunk_idx++;
        }
        return;
    }

    /* Non-LEND or small LEND: single slot */
    gunyah_add_mem_slot(s, base_hva, base_gpa, total_size, lend, flags);
}

static bool is_confidential_guest(void)
{
    GUNYAHState *s = GUNYAH_STATE(current_accel());

    /*
     * Protected VM if either:
     * - Explicit -accel gunyah,protected=on
     * - Legacy confidential-guest-support object
     */
    return s->protected_vm || current_machine->cgs != NULL;
}

/*
 * Check if memory of a confidential VM needs to be split into two portions -
 * one private to it and other shared with host.
 */
static bool split_mem(GUNYAHState *s,
        MemoryRegion *area, MemoryRegionSection *section)
{
    bool writeable = !area->readonly && !area->rom_device;

    if (!is_confidential_guest()) {
        return false;
    }

    if (!s->swiotlb_size || section->size <= s->swiotlb_size) {
        return false;
    }

    /* Split only memory that can be written to by guest */
    if (!memory_region_is_ram(area) || !writeable) {
        return false;
    }

    /* Have we reserved already? */
    if (qatomic_read(&s->preshmem_reserved)) {
        return false;
    }

    /* Do we have enough available memory? */
    if (section->size <= s->swiotlb_size) {
        return false;
    }

    return true;
}

static void gunyah_set_phys_mem(GUNYAHState *s,
        MemoryRegionSection *section, bool add)
{
    MemoryRegion *area = section->mr;
    bool writable = !area->readonly && !area->rom_device;
    enum gh_mem_flags flags = 0;
    uint64_t page_size = qemu_real_host_page_size();
    MemoryRegionSection mrs = *section;
    bool lend = is_confidential_guest(), split = false;
    struct gunyah_slot *slot;

    error_report("GH: set_phys_mem gpa=0x%"PRIx64" size=0x%"PRIx64
                 " add=%d is_ram=%d writable=%d lend=%d",
                 (uint64_t)section->offset_within_address_space,
                 (uint64_t)int128_get64(section->size),
                 add, memory_region_is_ram(area), writable, lend);

    /*
     * Gunyah hypervisor, at this time, does not support mapping memory
     * at low address (< 1GiB). Below code will be updated once
     * that limitation is addressed.
     *
     * Exception: ROM devices (pflash) are allowed through so the guest
     * can execute firmware directly from shared memory.  Without this,
     * instruction fetches from unmapped addresses cause stage-2 aborts
     * (not MMIO exits) and the firmware crashes immediately.
     */
    if (section->offset_within_address_space < GiB) {
        /* Gunyah MMIO window covers <1GiB — don't register these regions.
         * Log only once per address to avoid flooding (pflash toggles
         * ROMD/MMIO mode rapidly, which would OOM via GLib allocations). */
        static uint64_t last_skip_gpa = UINT64_MAX;
        uint64_t gpa = (uint64_t)section->offset_within_address_space;
        if (gpa != last_skip_gpa) {
            last_skip_gpa = gpa;
            error_report("GH: skipping region gpa=0x%"PRIx64" size=0x%"PRIx64
                         " (below 1GiB) is_ram=%d add=%d",
                         gpa, (uint64_t)int128_get64(section->size),
                         memory_region_is_ram(area), add);
        }
        return;
    }

    if (!memory_region_is_ram(area)) {
        if (writable) {
            return;
        } else if (!memory_region_is_romd(area)) {
            /*
             * If the memory device is not in romd_mode, then we actually want
             * to remove the gunyah memory slot so all accesses will trap.
             */
             add = false;
        }
    }

    if (!QEMU_IS_ALIGNED(int128_get64(section->size), page_size) ||
        !QEMU_IS_ALIGNED(section->offset_within_address_space, page_size)) {
        error_report("Not page aligned");
        add = false;
    }

    gunyah_slots_lock(s);

    slot = gunyah_find_overlap_slot(s,
            section->offset_within_address_space,
            int128_get64(section->size));

    if (!add) {
        if (slot) {
            error_report("Memory slot removal not yet supported!");
            exit(1);
        }
        /* Nothing to be done as address range was not previously registered */
        goto done;
    } else {
        if (slot) {
            error_report("Overlapping slot registration not supported!");
            exit(1);
        }

        if (qatomic_read(&s->vm_started)) {
            error_report("Memory map changes after VM start not supported!");
            exit(1);
        }
    }

    if (area->readonly || area->rom_device ||
        (!memory_region_is_ram(area) && memory_region_is_romd(area))) {
        /*
         * For ROM/readonly regions, we ideally want READ|EXEC only so
         * writes trap for CFI emulation.  However, Gunyah may require
         * WRITE permission for LEND'd memory to create proper stage-2
         * mappings.  Use READ|WRITE|EXEC for now (same as RAM), and
         * handle flash writes in the MMIO handler if needed.
         */
        flags = GH_MEM_ALLOW_READ | GH_MEM_ALLOW_WRITE | GH_MEM_ALLOW_EXEC;
    } else {
        flags = GH_MEM_ALLOW_READ | GH_MEM_ALLOW_WRITE | GH_MEM_ALLOW_EXEC;
    }

    /*
     * ROM devices (pflash) — always SHARE, never LEND.
     *
     * Flash MUST be LEND'd (not SHARE'd) because EDK2 PEIMs use XIP
     * (Execute-in-Place) from the FV: PeiDispatcher calls BLR X26 with
     * X26 pointing to an address in the flash VA range (e.g. 0x00021698).
     * The firmware's own page tables identity-map VA 0x0 → PA 0x0,
     * so instruction fetches go to GPA 0x0.  In protected VMs, SHARE'd
     * memory is NOT executable — only LEND'd memory gets exec permission
     * at stage-2.  Without LEND, the first PEIM dispatch causes a silent
     * stage-2 instruction abort that kills the vCPU.
     *
     * Flags are READ|EXEC (no WRITE), so guest writes to flash still
     * cause stage-2 faults → MMIO exits → QEMU pflash CFI handling.
     *
     * Note: the firmware is ALSO copied to RAM at 0x80000000 (LEND'd)
     * for the initial boot stub and PeiCore.  Both copies coexist:
     * PeiCore/SEC run from RAM copy (with our trampolines/patches),
     * PEIMs run XIP from flash copy (original unpatched code).
     */
    /* rom_device: let default lend=true stand for protected VMs */

    split = split_mem(s, area, &mrs);
    if (split) {
        mrs.size -= s->swiotlb_size;
        gunyah_add_mem(s, &mrs, true, flags);
        lend = false;
        mrs.offset_within_region += mrs.size;
        mrs.offset_within_address_space += mrs.size;
        mrs.size = s->swiotlb_size;
        qatomic_set(&s->preshmem_reserved, true);
    }

    gunyah_add_mem(s, &mrs, lend, flags);

done:
    gunyah_slots_unlock(s);
}

static void gunyah_region_add(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    GUNYAHState *s = GUNYAH_STATE(current_accel());

    gunyah_set_phys_mem(s, section, true);
}

static void gunyah_region_del(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    GUNYAHState *s = GUNYAH_STATE(current_accel());

    gunyah_set_phys_mem(s, section, false);
}

void gunyah_set_swiotlb_size(uint64_t size)
{
    GUNYAHState *s = GUNYAH_STATE(current_accel());

    s->swiotlb_size = size;
}

/*
 * Cached LEND range for lock-free checking in the hot path.
 * Set once during gunyah_start_vm() and never changes after.
 */
static uint64_t gunyah_lend_start;
static uint64_t gunyah_lend_end;

void gunyah_cache_lend_range(void)
{
    GUNYAHState *s = GUNYAH_STATE(current_accel());
    int i;

    if (!s->protected_vm) {
        return;
    }

    for (i = 0; i < s->nr_slots; i++) {
        gunyah_slot *slot = &s->slots[i];
        if (slot->size && slot->lend) {
            gunyah_lend_start = slot->start;
            gunyah_lend_end = slot->start + slot->size;
            error_report("GH: cached LEND range: 0x%"PRIx64" - 0x%"PRIx64,
                         gunyah_lend_start, gunyah_lend_end);
            return;
        }
    }
}

bool gunyah_addr_is_lend(uint64_t gpa)
{
    /* Lock-free: uses cached range set before VM_START */
    return gpa >= gunyah_lend_start && gpa < gunyah_lend_end;
}

int gunyah_add_irqfd(int irqfd, int label, Error **errp)
{
    int ret;
    struct gh_fn_desc fdesc;
    struct gh_fn_irqfd_arg ghirqfd;

    fdesc.type = GH_FN_IRQFD;
    fdesc.arg_size = sizeof(struct gh_fn_irqfd_arg);
    fdesc.arg = (__u64)(&ghirqfd);

    ghirqfd.fd = irqfd;
    ghirqfd.label = label;
    ghirqfd.flags = GH_IRQFD_FLAGS_LEVEL;

    error_report("GH: add_irqfd label=%d fd=%d flags=0x%x",
                 label, irqfd, ghirqfd.flags);
    ret = gunyah_vm_ioctl(GH_VM_ADD_FUNCTION, &fdesc);
    if (ret) {
        error_report("GH: add_irqfd FAILED label=%d: %s (errno=%d)",
                     label, strerror(errno), errno);
        error_setg_errno(errp, errno, "GH_FN_IRQFD failed");
    } else {
        error_report("GH: add_irqfd OK label=%d", label);
    }

    return ret;
}

static int gunyah_set_ioeventfd_mmio(int fd, hwaddr addr,
        uint32_t size, uint32_t data, bool datamatch, bool assign)
{
    int ret;
    struct gh_fn_ioeventfd_arg io;
    struct gh_fn_desc fdesc;

    io.fd = fd;
    io.datamatch = datamatch ? data : 0;
    io.len = size;
    io.addr = addr;
    io.flags = datamatch ? GH_IOEVENTFD_FLAGS_DATAMATCH : 0;

    fdesc.type = GH_FN_IOEVENTFD;
    fdesc.arg_size = sizeof(struct gh_fn_ioeventfd_arg);
    fdesc.arg = (__u64)(&io);

    if (assign) {
        ret = gunyah_vm_ioctl(GH_VM_ADD_FUNCTION, &fdesc);
    } else {
        ret = gunyah_vm_ioctl(GH_VM_REMOVE_FUNCTION, &fdesc);
    }

    return ret;
}

static void gunyah_mem_ioeventfd_add(MemoryListener *listener,
                                  MemoryRegionSection *section,
                                  bool match_data, uint64_t data,
                                  EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;

    error_report("GH: ioeventfd_add addr=0x%"PRIx64" size=0x%"PRIx64
                 " fd=%d match=%d data=0x%"PRIx64,
                 (uint64_t)section->offset_within_address_space,
                 (uint64_t)int128_get64(section->size),
                 fd, match_data, data);

    /*
     * Note: We no longer skip IOEVENTFDs for addresses below 1 GiB.
     * Virtio-mmio transports live at 0x0a000000 and need ioeventfd for
     * efficient QUEUE_NOTIFY handling.  The memory region skip (no RAM
     * mapping below 1GiB) is separate — ioeventfds work on MMIO exits,
     * not RAM.  If the kernel driver doesn't support ioeventfd at this
     * address, the ioctl will fail and we fall back to MMIO exit path.
     */
    r = gunyah_set_ioeventfd_mmio(fd, section->offset_within_address_space,
                               int128_get64(section->size), data, match_data,
                               true);
    if (r < 0) {
        error_report("GH: ioeventfd_add failed addr=0x%"PRIx64": %s (errno=%d) "
                     "— falling back to MMIO exit path (slower but functional)",
                     (uint64_t)section->offset_within_address_space,
                     strerror(errno), errno);
        /* Non-fatal: virtio will still work via MMIO exits, just slower */
    }
}

static void gunyah_mem_ioeventfd_del(MemoryListener *listener,
                                  MemoryRegionSection *section,
                                  bool match_data, uint64_t data,
                                  EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;

    r = gunyah_set_ioeventfd_mmio(fd, section->offset_within_address_space,
                               int128_get64(section->size), data, match_data,
                               false);
    if (r < 0) {
        /* Non-fatal: if add failed, del will also fail */
    }
}

GUNYAHState *get_gunyah_state(void)
{
    return GUNYAH_STATE(current_accel());
}

static void gunyah_ipi_signal(int sig)
{
    if (current_cpu) {
        qatomic_set(&current_cpu->accel->run->immediate_exit, 1);
    }
}

static void gunyah_cpu_kick_self(void)
{
    qatomic_set(&current_cpu->accel->run->immediate_exit, 1);
}

static int gunyah_init_vcpu(CPUState *cpu, Error **errp)
{
    int ret;
    struct sigaction sigact;
    sigset_t set;

    cpu->accel = g_new0(AccelCPUState, 1);
    cpu->accel->fd = -1;

    /*
     * Allocate a dummy page for the vcpu run struct so that signal handlers
     * (gunyah_ipi_signal, gunyah_cpu_kick_self) can safely access
     * cpu->accel->run->immediate_exit before the real VCPU fd is created.
     *
     * The actual GH_VM_ADD_FUNCTION(VCPU) ioctl is deferred to
     * gunyah_start_vm(), which runs on the main thread AFTER all memory
     * has been registered. This matches CrosVM's ordering:
     *   memory registration → VCPU creation → DTB config → VM_START
     */
    cpu->accel->run = mmap(0, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (cpu->accel->run == MAP_FAILED) {
        error_report("mmap of dummy vcpu run page failed: %s",
                     strerror(errno));
        exit(1);
    }

    /* init cpu signals */
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = gunyah_ipi_signal;
    sigaction(SIG_IPI, &sigact, NULL);

    pthread_sigmask(SIG_BLOCK, NULL, &set);
    sigdelset(&set, SIG_IPI);

    ret = pthread_sigmask(SIG_SETMASK, &set, NULL);
    if (ret) {
        error_report("pthread_sigmask: %s", strerror(ret));
        exit(1);
    }

    error_report("GH: init_vcpu %d (deferred - VCPU will be created at VM start)",
                 cpu->cpu_index);
    return 0;
}

static void gunyah_vcpu_destroy(CPUState *cpu)
{
    int ret;

    ret = munmap(cpu->accel->run, 4096);
    if (ret < 0) {
        error_report("munmap of vcpu run structure failed: %s",
                strerror(errno));
        exit(1);
    }

    close(cpu->accel->fd);
    g_free(cpu->accel);
}

static void gunyah_dump_vm_state(GUNYAHState *s)
{
    int i;

    error_report("=== Gunyah VM state before GH_VM_START ===");
    error_report("  fd=%d vmfd=%d protected=%d swiotlb_size=0x%"PRIx64,
                 s->fd, s->vmfd, s->protected_vm, s->swiotlb_size);
    error_report("  nr_slots=%u nr_irqs=%u preshmem_reserved=%d",
                 s->nr_slots, s->nr_irqs, s->preshmem_reserved);

    for (i = 0; i < s->nr_slots; ++i) {
        if (s->slots[i].size == 0) {
            continue;
        }
        error_report("  slot[%d]: gpa=0x%"PRIx64" size=0x%"PRIx64
                     " hva=%p lend=%d id=%u flags=0x%x",
                     i, s->slots[i].start, s->slots[i].size,
                     s->slots[i].mem, s->slots[i].lend,
                     s->slots[i].id, s->slots[i].flags);
    }
    error_report("=== End Gunyah VM state ===");
}

void gunyah_start_vm(void)
{
    int ret, i;
    GUNYAHState *s = GUNYAH_STATE(current_accel());
    CPUState *cpu;

    gunyah_dump_vm_state(s);
    gunyah_cache_lend_range();

    if (!s->protected_vm) {
        error_report("GH: *** WARNING: protected_vm=false ***");
        error_report("GH: This means ALL memory uses GH_VM_SET_USER_MEM_REGION "
                     "(SHARE), NOT GH_VM_ANDROID_LEND_USER_MEM (LEND).");
        error_report("GH: CrosVM's --protected-vm-without-firmware uses LEND.");
        error_report("GH: If this fails, try: -accel gunyah,protected=on");
    } else {
        error_report("GH: protected_vm=true: memory split into LEND + SHARE "
                     "(swiotlb=0x%"PRIx64")", s->swiotlb_size);
    }

    /*
     * Match CrosVM's exact ioctl ordering (confirmed via strace):
     *
     *   LEND → SHARE → ADD_FUNCTION(VCPU) → ADD_FUNCTION(IRQFD) × 5
     *   → SET_DTB_CONFIG → SET_BOOT_CONTEXT(PC) → VM_START
     *
     * CRITICAL: VCPUs and IRQFDs MUST be registered BEFORE VM_START.
     * The kernel driver's gunyah_vm_start() needs these function instances
     * so that RM can allocate proper resources during VM_INIT.
     */

    /* Step 1: Create VCPUs BEFORE VM_START */
    CPU_FOREACH(cpu) {
        struct gh_fn_desc fdesc;
        struct gh_fn_vcpu_arg vcpu_arg;

        vcpu_arg.id = cpu->cpu_index;
        fdesc.type = GH_FN_VCPU;
        fdesc.arg_size = sizeof(struct gh_fn_vcpu_arg);
        fdesc.arg = (__u64)(&vcpu_arg);

        error_report("GH: creating vCPU %d (BEFORE VM_START, matching CrosVM strace)",
                     vcpu_arg.id);
        ghdbg_hexdump("VCPU gh_fn_desc", &fdesc, sizeof(fdesc));
        ghdbg_hexdump("VCPU gh_fn_vcpu_arg", &vcpu_arg, sizeof(vcpu_arg));
        ret = gunyah_vm_ioctl(GH_VM_ADD_FUNCTION, &fdesc);
        if (ret < 0) {
            error_report("could not create VCPU %d: %s (errno=%d)",
                         vcpu_arg.id, strerror(errno), errno);
            exit(1);
        }
        error_report("GH: vCPU %d created, fd=%d", vcpu_arg.id, ret);

        /* Replace dummy anonymous page with real vcpu run struct */
        munmap(cpu->accel->run, 4096);
        cpu->accel->fd = ret;
        cpu->accel->run = mmap(0, 4096, PROT_READ | PROT_WRITE,
                               MAP_SHARED, ret, 0);
        if (cpu->accel->run == MAP_FAILED) {
            error_report("mmap of vcpu run structure failed: %s",
                         strerror(errno));
            exit(1);
        }
    }

    /*
     * Step 2: Create IRQFDs for doorbells BEFORE VM_START.
     *
     * Base doorbells (from CrosVM) plus PCI INTx doorbells:
     *   bell-0: label=0  (serial,    EDGE_RISING)
     *   bell-1: label=1  (RTC,       EDGE_RISING)
     *   bell-2: label=2  (serial,    EDGE_RISING)
     *   bell-3: label=3  (PCI INTA,  LEVEL_HIGH)
     *   bell-4: label=4  (PCI INTB,  LEVEL_HIGH)
     *   bell-5: label=5  (PCI INTC,  LEVEL_HIGH)
     *   bell-6: label=6  (PCI INTD,  LEVEL_HIGH)
     *   bell-f: label=15 (vmwdt,     EDGE_RISING)
     * PCI eventfds are also registered as GIC notifiers so QEMU's
     * GPEX controller can inject interrupts via doorbell.
     */
    {
        struct { int label; int flags; } bells[] = {
            { 0x0, 0 },                     /* EDGE_RISING - serial */
            { 0x1, GH_IRQFD_FLAGS_LEVEL },  /* LEVEL_HIGH  - PL011 UART */
            { 0x2, 0 },                     /* EDGE_RISING - serial */
            { 0x3, GH_IRQFD_FLAGS_LEVEL },  /* LEVEL_HIGH  - PCI INTA */
            { 0x4, GH_IRQFD_FLAGS_LEVEL },  /* LEVEL_HIGH  - PCI INTB */
            { 0x5, GH_IRQFD_FLAGS_LEVEL },  /* LEVEL_HIGH  - PCI INTC */
            { 0x6, GH_IRQFD_FLAGS_LEVEL },  /* LEVEL_HIGH  - PCI INTD */
            { 0xf, 0 },                     /* EDGE_RISING - vmwdt */
        };
        int nbell = sizeof(bells) / sizeof(bells[0]);

        /*
         * PL011 notifier: save bell-1 eventfd for SPI 1 so we can
         * register it with the GIC model for PL011 RX interrupts.
         */
        EventNotifier pl011_notifier;
        int pl011_notifier_valid = 0;

        /*
         * PCI INTx notifiers: save eventfds for SPIs 3-6 so we can
         * register them with the GIC model after creating IRQFDs.
         */
        #define PCI_FIRST_SPI 3
        #define PCI_NUM_SPIS  4
        EventNotifier pci_notifiers[PCI_NUM_SPIS];
        int pci_notifiers_valid[PCI_NUM_SPIS];
        memset(pci_notifiers_valid, 0, sizeof(pci_notifiers_valid));

        error_report("GH: creating %d IRQFDs (base + PCI)", nbell);

        for (i = 0; i < nbell; ++i) {
            struct gh_fn_desc fdesc;
            struct gh_fn_irqfd_arg ghirqfd = {0};
            int efd;

            efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            if (efd < 0) {
                error_report("GH: eventfd failed for bell-%x: %s",
                             bells[i].label, strerror(errno));
                exit(1);
            }

            /* Save PL011 eventfd for GIC notifier registration (SPI 1) */
            if (bells[i].label == 0x1) {
                event_notifier_init_fd(&pl011_notifier, efd);
                pl011_notifier_valid = 1;
            }

            /* Save PCI eventfds for GIC notifier registration */
            if (bells[i].label >= PCI_FIRST_SPI &&
                bells[i].label < PCI_FIRST_SPI + PCI_NUM_SPIS) {
                int idx = bells[i].label - PCI_FIRST_SPI;
                event_notifier_init_fd(&pci_notifiers[idx], efd);
                pci_notifiers_valid[idx] = 1;
            }

            ghirqfd.fd = efd;
            ghirqfd.label = bells[i].label;
            ghirqfd.flags = bells[i].flags;
            ghirqfd.padding = 0;

            fdesc.type = GH_FN_IRQFD;
            fdesc.arg_size = sizeof(struct gh_fn_irqfd_arg);
            fdesc.arg = (__u64)(&ghirqfd);

            error_report("GH: IRQFD bell-%x label=%d efd=%d flags=0x%x",
                         bells[i].label, bells[i].label, efd, bells[i].flags);
            ghdbg_hexdump("IRQFD gh_fn_desc", &fdesc, sizeof(fdesc));
            ghdbg_hexdump("IRQFD gh_fn_irqfd_arg", &ghirqfd, sizeof(ghirqfd));
            ret = gunyah_vm_ioctl(GH_VM_ADD_FUNCTION, &fdesc);
            if (ret != 0) {
                error_report("GH: IRQFD bell-%x FAILED: %s (errno=%d)",
                             bells[i].label, strerror(errno), errno);
                /* Non-fatal: continue anyway */
            } else {
                error_report("GH: IRQFD bell-%x OK", bells[i].label);
            }
        }

        /* Register PL011 eventfd as GIC notifier for SPI 1 */
        if (pl011_notifier_valid) {
            gunyah_gic_register_irq_notifiers(&pl011_notifier, 1, 1);
            error_report("GH: PL011 GIC notifier registered for SPI 1");
        }

        /* Register PCI eventfds as GIC notifiers for SPIs 3-6 */
        gunyah_gic_register_irq_notifiers(pci_notifiers,
                                          PCI_NUM_SPIS, PCI_FIRST_SPI);
        #undef PCI_FIRST_SPI
        #undef PCI_NUM_SPIS
    }

    /*
     * Step 2b: Create IRQFDs for virtio-mmio doorbells (labels 0x10-0x2f).
     * These map to SPIs 16-47, matching QEMU virt's virtio transport IRQs.
     * The eventfds are registered with the GIC so that when QEMU's virtio
     * device models raise IRQs, the eventfd fires → Gunyah doorbell →
     * guest GIC SPI.
     */
    {
        #define NUM_VIRTIO_BELLS 32
        EventNotifier virtio_notifiers[NUM_VIRTIO_BELLS];
        int virtio_ok = 0;

        error_report("GH: creating %d virtio IRQFDs (labels 0x10-0x2f, "
                     "SPIs 16-47)", NUM_VIRTIO_BELLS);

        for (i = 0; i < NUM_VIRTIO_BELLS; i++) {
            struct gh_fn_desc fdesc;
            struct gh_fn_irqfd_arg ghirqfd = {0};
            int efd;
            int label = 0x10 + i;

            efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            if (efd < 0) {
                error_report("GH: eventfd failed for virtio bell-%x: %s",
                             label, strerror(errno));
                continue;
            }

            event_notifier_init_fd(&virtio_notifiers[i], efd);

            ghirqfd.fd = efd;
            ghirqfd.label = label;
            ghirqfd.flags = 0;  /* EDGE */
            ghirqfd.padding = 0;

            fdesc.type = GH_FN_IRQFD;
            fdesc.arg_size = sizeof(struct gh_fn_irqfd_arg);
            fdesc.arg = (__u64)(&ghirqfd);

            ret = gunyah_vm_ioctl(GH_VM_ADD_FUNCTION, &fdesc);
            if (ret != 0) {
                error_report("GH: IRQFD virtio bell-%x FAILED: %s (errno=%d)",
                             label, strerror(errno), errno);
            } else {
                virtio_ok++;
            }
        }

        error_report("GH: %d/%d virtio IRQFDs created OK",
                     virtio_ok, NUM_VIRTIO_BELLS);

        /* Register notifiers with GIC for IRQ injection */
        gunyah_gic_register_irq_notifiers(virtio_notifiers,
                                          NUM_VIRTIO_BELLS, 16);
        #undef NUM_VIRTIO_BELLS
    }

    /* Step 3: SET_DTB_CONFIG */
    if (s->dtb_start) {
        struct gh_vm_dtb_config dtb;

        dtb.guest_phys_addr = s->dtb_start;
        dtb.size = s->dtb_size;

        error_report("GH: SET_DTB_CONFIG gpa=0x%"PRIx64" size=0x%"PRIx64,
                     (uint64_t)dtb.guest_phys_addr, (uint64_t)dtb.size);
        ghdbg_hexdump("SET_DTB_CONFIG gh_vm_dtb_config", &dtb, sizeof(dtb));

        /* Show which memory slot contains the DTB */
        for (i = 0; i < s->nr_slots; ++i) {
            if (s->slots[i].size == 0) continue;
            uint64_t slot_end = s->slots[i].start + s->slots[i].size;
            if (dtb.guest_phys_addr >= s->slots[i].start &&
                dtb.guest_phys_addr < slot_end) {
                error_report("GH: DTB falls in slot[%d] gpa=0x%"PRIx64
                             " size=0x%"PRIx64" lend=%d (offset=0x%"PRIx64")",
                             i, s->slots[i].start, s->slots[i].size,
                             s->slots[i].lend,
                             (uint64_t)(dtb.guest_phys_addr - s->slots[i].start));
            }
        }

        /* Verify DTB content is populated - dump first 64 bytes at DTB HVA */
        for (i = 0; i < s->nr_slots; ++i) {
            if (s->slots[i].size == 0) continue;
            uint64_t slot_end = s->slots[i].start + s->slots[i].size;
            if (dtb.guest_phys_addr >= s->slots[i].start &&
                dtb.guest_phys_addr < slot_end) {
                uint64_t offset = dtb.guest_phys_addr - s->slots[i].start;
                void *dtb_hva = (uint8_t *)s->slots[i].mem + offset;
                error_report("GH: DTB content at HVA %p (slot[%d] + 0x%"PRIx64"):",
                             dtb_hva, i, offset);
                ghdbg_hexdump("DTB first 64 bytes", dtb_hva, 64);
                /* Check FDT magic */
                uint32_t magic = *(uint32_t *)dtb_hva;
                error_report("GH: DTB magic=0x%08x (%s)",
                             magic,
                             magic == 0xd00dfeed ? "VALID (big-endian)"
                             : magic == 0xedfe0dd0 ? "VALID (needs swap)"
                             : "INVALID!");
                break;
            }
        }

        ret = gunyah_vm_ioctl(GH_VM_SET_DTB_CONFIG, &dtb);
        if (ret != 0) {
            error_report("GH_VM_SET_DTB_CONFIG failed: %s (errno=%d)",
                         strerror(errno), errno);
            exit(1);
        }
        error_report("GH: SET_DTB_CONFIG OK");
    }

    /*
     * Firmware boot path: EDK2 is loaded directly into RAM at VIRT_MEM.base
     * (0x80000000) by virt.c's virt_firmware_init() when -bios is used with
     * Gunyah. The firmware is compiled with PcdFdBaseAddress=0x80000000 and
     * PcdSystemMemoryBase=0x80000000, so no address relocation is needed.
     *
     * When no -kernel is specified, s->kernel_entry will be 0. The boot
     * stub below falls back to kernel_load_addr (first LEND'd slot start =
     * 0x80000000), which is exactly where the firmware was loaded.
     */

    /*
     * Step 3.5b: Detect CrosVM boot wrapper and find real kernel entry.
     *
     * CrosVM kernels often have a small boot wrapper at offset 0 that:
     *   ldr x0, =<dtb_addr>    // hardcoded DTB address
     *   mov x1-x3, xzr
     *   ldr x4, =<entry>       // actual kernel entry
     *   br  x4
     *
     * We detect this pattern and extract the real kernel entry point.
     * Then our boot stub jumps directly to the real kernel, bypassing
     * the wrapper (which would override X0 with a wrong DTB address).
     *
     * The stub writes "QEMU\r\n" to UART at 0x09000000 via MMIO,
     * preserves X0 (DTB from RM), and jumps to the real kernel.
     */
    {
        uint64_t kernel_entry = 0;
        uint64_t kernel_load_addr = 0;
        uint64_t kernel_slot_size = 0;
        void *kernel_hva_base = NULL;
        uint64_t stub_gpa;
        void *stub_hva = NULL;

        /* Find kernel load address and HVA (in LEND'd RAM, not pflash) */
        for (i = 0; i < s->nr_slots; ++i) {
            if (s->slots[i].size > 0 && s->slots[i].lend) {
                kernel_load_addr = s->slots[i].start;
                kernel_hva_base = s->slots[i].mem;
                kernel_slot_size = s->slots[i].size;
                break;
            }
        }
        kernel_entry = kernel_load_addr;

        /*
         * Find the actual kernel entry point.
         *
         * QEMU's load_aarch64_image() loads the kernel Image at
         * mem_base + text_offset, NOT at mem_base.  At mem_base (offset 0)
         * QEMU writes its own secondary-CPU bootloader (ARM32 code).
         *
         * Priority:
         *  1. Use s->kernel_entry set by virt.c from arm_boot_info.entry
         *  2. Check for CrosVM boot wrapper at offset 0
         *  3. Fall back to slot start (probably wrong, but last resort)
         */
        if (s->kernel_entry) {
            /* arm_load_kernel() already told us the entry point */
            kernel_entry = s->kernel_entry;
            error_report("GH: Using kernel_entry=0x%"PRIx64
                         " from arm_load_kernel()", kernel_entry);
        } else if (kernel_hva_base) {
            /*
             * Check for CrosVM boot wrapper pattern at offset 0:
             *   offset 0x04: mov x1, xzr (0xaa1f03e1)
             *   offset 0x08: mov x2, xzr (0xaa1f03e2)
             *   offset 0x0c: mov x3, xzr (0xaa1f03e3)
             */
            uint32_t *insns = (uint32_t *)kernel_hva_base;
            if (insns[1] == 0xaa1f03e1 &&  /* mov x1, xzr */
                insns[2] == 0xaa1f03e2 &&  /* mov x2, xzr */
                insns[3] == 0xaa1f03e3) {  /* mov x3, xzr */

                uint64_t wrapper_entry =
                    *(uint64_t *)((uint8_t *)kernel_hva_base + 0x20);

                error_report("GH: Detected CrosVM boot wrapper at 0x%"PRIx64,
                             kernel_load_addr);
                kernel_entry = wrapper_entry;
                error_report("GH: Using real kernel entry 0x%"PRIx64
                             " (skipping CrosVM wrapper)", kernel_entry);
            } else {
                error_report("GH: WARNING: kernel_entry not set by machine "
                             "and no CrosVM wrapper detected, "
                             "using kernel_entry=0x%"PRIx64, kernel_entry);
            }
        }

        stub_gpa = s->dtb_start - 0x1000;

        /* Find the HVA for the stub GPA */
        for (i = 0; i < s->nr_slots; ++i) {
            if (s->slots[i].size > 0 &&
                stub_gpa >= s->slots[i].start &&
                stub_gpa < s->slots[i].start + s->slots[i].size) {
                uint64_t offset = stub_gpa - s->slots[i].start;
                stub_hva = s->slots[i].mem + offset;
                break;
            }
        }

        if (stub_hva) {
            /*
             * ARM64 machine code stub (preserves X0 = DTB addr from RM):
             *   mov  x4, x0                 ; save DTB pointer
             *   movz x5, #0x0900, lsl #16   ; x5 = 0x09000000 (UART)
             *   movz w6, #'Q'               ; character
             *   str  w6, [x5]               ; write to UART (MMIO exit)
             *   movz w6, #'E'
             *   str  w6, [x5]
             *   movz w6, #'M'
             *   str  w6, [x5]
             *   movz w6, #'U'
             *   str  w6, [x5]
             *   movz w6, #'\r'
             *   str  w6, [x5]
             *   movz w6, #'\n'
             *   str  w6, [x5]
             *   mov  x0, x4                 ; restore DTB pointer
             *   mov  x1, xzr                ; x1=0 per ARM64 boot protocol
             *   mov  x2, xzr                ; x2=0
             *   mov  x3, xzr                ; x3=0
             *   movz x4, #<bits 15:0>       ; kernel entry low 16 bits
             *   movk x4, #<bits 31:16>, lsl #16
             *   br   x4                     ; jump to kernel
             */
            uint32_t stub[] = {
                0xAA0003E4, /* mov  x4, x0  (save DTB addr) */
                0xD2A12005, /* movz x5, #0x0900, lsl #16 */
                0x52800A26, /* movz w6, #'Q' (0x51) */
                0xB90000A6, /* str  w6, [x5] */
                0x528008A6, /* movz w6, #'E' (0x45) */
                0xB90000A6, /* str  w6, [x5] */
                0x528009A6, /* movz w6, #'M' (0x4D) */
                0xB90000A6, /* str  w6, [x5] */
                0x52800AA6, /* movz w6, #'U' (0x55) */
                0xB90000A6, /* str  w6, [x5] */
                0x528001A6, /* movz w6, #'\r' (0x0D) */
                0xB90000A6, /* str  w6, [x5] */
                0x52800146, /* movz w6, #'\n' (0x0A) */
                0xB90000A6, /* str  w6, [x5] */
                0xAA0403E0, /* mov  x0, x4  (restore DTB addr) */
                0xAA1F03E1, /* mov  x1, xzr */
                0xAA1F03E2, /* mov  x2, xzr */
                0xAA1F03E3, /* mov  x3, xzr */
                /* movz x4, #(kernel_entry & 0xFFFF) */
                (uint32_t)(0xD2800004 |
                    ((kernel_entry & 0xFFFF) << 5)),
                /* movk x4, #(kernel_entry >> 16), lsl #16 */
                (uint32_t)(0xF2A00004 |
                    (((kernel_entry >> 16) & 0xFFFF) << 5)),
                0xD61F0080, /* br x4 */
            };
            memcpy(stub_hva, stub, sizeof(stub));
            error_report("GH: Injected boot stub at GPA=0x%"PRIx64
                         " (writes 'QEMU\\r\\n' to UART 0x09000000, "
                         "then jumps to kernel at 0x%"PRIx64")",
                         stub_gpa, kernel_entry);
        } else {
            error_report("GH: WARNING: could not find HVA for stub "
                         "GPA=0x%"PRIx64", skipping boot stub",
                         stub_gpa);
            stub_gpa = kernel_entry; /* fall back to direct kernel entry */
        }

        /* Step 4: SET_BOOT_CONTEXT PC → stub (or kernel if stub failed) */
        {
            struct gh_vm_boot_context boot_ctx = {0};
            boot_ctx.reg = (GH_VM_BOOT_CONTEXT_REG_SET_PC
                            << GH_VM_BOOT_CONTEXT_REG_SHIFT) | 0;
            boot_ctx.value = stub_gpa;
            error_report("GH: SET_BOOT_CONTEXT PC=0x%"PRIx64,
                         (uint64_t)boot_ctx.value);
            ghdbg_hexdump("SET_BOOT_CONTEXT gh_vm_boot_context",
                          &boot_ctx, sizeof(boot_ctx));
            ret = gunyah_vm_ioctl(GH_VM_SET_BOOT_CONTEXT, &boot_ctx);
            if (ret != 0) {
                if (errno == ENOTTY) {
                    error_report("GH: SET_BOOT_CONTEXT not supported (ENOTTY)");
                } else {
                    error_report("GH: SET_BOOT_CONTEXT PC failed: %s (errno=%d)",
                                 strerror(errno), errno);
                }
            } else {
                error_report("GH: SET_BOOT_CONTEXT PC OK");
            }
        }

        error_report("GH: skipping X0 (RM sets X0=DTB from SET_DTB_CONFIG)");
    }

vm_start:
    /*
     * Firmware content verification: dump first 32 bytes of each slot
     * to verify the firmware data is present in the LEND'd pages.
     * For -bios, load_image_mr() runs AFTER the LEND ioctl, so data
     * should have been written to the same memfd-backed pages.
     */
    for (i = 0; i < s->nr_slots; ++i) {
        if (s->slots[i].size > 0 && s->slots[i].mem) {
            error_report("GH: pre-VM_START slot[%d] gpa=0x%"PRIx64
                         " lend=%d first 32 bytes:",
                         i, s->slots[i].start, s->slots[i].lend);
            ghdbg_hexdump("slot content", s->slots[i].mem, 32);
        }
    }

    /*
     * Reinstall our SIGBUS handler — QEMU's qemu_init_sigbus() in cpus.c
     * installed its own handler earlier, which just re-raises without any
     * diagnostic output.  Ours prints memory slots, registers, backtrace.
     */
    gunyah_install_sigsegv_handler();

    /* Step 5: VM_START */
    ret = gunyah_vm_ioctl(GH_VM_START);
    if (ret != 0) {
        error_report("Failed to start VM: %s (errno=%d)", strerror(errno), errno);
        exit(1);
    }
    error_report("GH: VM_START OK");

    /*
     * After VM_START, the LEND'd physical pages belong to the hypervisor.
     * The host CPU can no longer access them — any read/write triggers a
     * synchronous external abort.
     *
     * Problem: kswapd's deferred_split_scan() still has references to these
     * pages and will try to inspect them (memchr_inv), causing a kernel panic:
     *   Internal error: synchronous external abort: 0000000096000010
     *   pc: memchr_inv+0x114/0x270
     *   lr: deferred_split_scan+0x358/0x628
     *
     * Fix: MADV_DONTNEED drops the page table entries and releases the pages
     * from the kernel's tracking structures (LRU lists, deferred_split_queue).
     * Then mprotect(PROT_NONE) prevents any future faults from re-establishing
     * mappings to those pages.
     */
    for (i = 0; i < s->nr_slots; i++) {
        gunyah_slot *slot = &s->slots[i];
        if (slot->size && slot->lend && slot->mem) {
            void *base = slot->mem;
            size_t sz = slot->size;

            /* Unlock pages now that LEND has pinned them */
            munlock(base, sz);
            error_report("GH: LEND region hva=%p size=0x%zx post-start "
                         "munlock done", base, sz);
        }
    }

    qatomic_set(&s->vm_started, 1);
}

/* Track whether the VM has received a terminal status exit */
static bool gunyah_vm_stopped;

static int gunyah_vcpu_exec(CPUState *cpu)
{
    int ret;
    enum gh_vm_status exit_status;
    enum gh_vm_exit_type exit_type;

    if (cpu->accel->fd < 0) {
        error_report("GH: ERROR: vcpu fd is %d (invalid!)", cpu->accel->fd);
        return EXCP_INTERRUPT;
    }

    /* Don't re-enter after VM shutdown/crash */
    if (qatomic_read(&gunyah_vm_stopped)) {
        return EXCP_INTERRUPT;
    }

    bql_unlock();
    cpu_exec_start(cpu);

    do {
        struct gh_vcpu_run *run = cpu->accel->run;
        int exit_reason;
        static uint64_t vcpu_run_count;

        if (qatomic_read(&cpu->exit_request)) {
            gunyah_cpu_kick_self();
        }

        ret = gunyah_vcpu_ioctl(cpu, GH_VCPU_RUN);
        vcpu_run_count++;

        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                qatomic_set(&run->immediate_exit, 0);
                ret = EXCP_INTERRUPT;
                break;
            }

            /*
             * ENODEV on secondary CPUs means the vCPU hasn't been powered
             * on yet via PSCI CPU_ON.  Gunyah handles PSCI internally;
             * the VMM just needs to wait and retry.  Sleep briefly to
             * avoid busy-spinning, then loop back to GH_VCPU_RUN which
             * will block once the vCPU is powered on.
             */
            if (errno == ENODEV) {
                /*
                 * ENODEV means the vCPU isn't runnable right now.
                 * Two cases:
                 *  1) Secondary CPU waiting for PSCI CPU_ON — retry
                 *  2) After guest shutdown — stop retrying
                 */
                if (qatomic_read(&gunyah_vm_stopped) ||
                    qatomic_read(&cpu->exit_request) ||
                    cpu->cpu_index == 0) {
                    ret = EXCP_INTERRUPT;
                    break;
                }
                /* Secondary CPU waiting for PSCI CPU_ON */
                usleep(10000);  /* 10ms */
                ret = 0;
                continue;
            }

            error_report("GH_VCPU_RUN: %s (errno=%d)", strerror(errno), errno);
            ret = -1;
            break;
        }

        exit_reason = run->exit_reason;
        switch (exit_reason) {
        case GH_VCPU_EXIT_MMIO:
        {
            uint64_t mmio_addr = run->mmio.phys_addr;

            /*
             * UART MMIO at 0x09000000 — earlycon support only.
             *
             * Writes are forwarded to the PL011 device model.
             * Reads at offset 0x05 (8250 LSR with byte-spacing) return
             * 0x60 (THRE | TEMT) so earlycon always sees "TX ready".
             * All other reads are forwarded to PL011.
             */
            if (mmio_addr >= 0x09000000 && mmio_addr < 0x09001000) {
                uint32_t offset = mmio_addr & 0xFFF;

                if (run->mmio.is_write) {
                    /* Forward write to PL011 */
                    bql_lock();
                    address_space_rw(&address_space_memory,
                        mmio_addr, MEMTXATTRS_UNSPECIFIED,
                        run->mmio.data, run->mmio.len, true);
                    bql_unlock();
                } else if (offset == 0x14 || offset == 0x05) {
                    /* earlycon LSR: always TX ready (0x14 = mmio32, 0x05 = byte) */
                    memset(run->mmio.data, 0, run->mmio.len);
                    run->mmio.data[0] = 0x60;
                } else {
                    /* Forward read to PL011 */
                    bql_lock();
                    address_space_rw(&address_space_memory,
                        mmio_addr, MEMTXATTRS_UNSPECIFIED,
                        run->mmio.data, run->mmio.len, false);
                    bql_unlock();
                }
            } else {
                /* Non-UART MMIO - dispatch to device model */
                static int non_uart_count;
                MemTxResult mr;
                bql_lock();
                mr = address_space_rw(&address_space_memory,
                    mmio_addr, MEMTXATTRS_UNSPECIFIED,
                    run->mmio.data, run->mmio.len,
                    run->mmio.is_write);
                bql_unlock();
                if (non_uart_count < 50) {
                    uint32_t val = 0;
                    if (run->mmio.len == 4 && !run->mmio.is_write) {
                        memcpy(&val, run->mmio.data, 4);
                    }
                    error_report("GH: non-UART MMIO #%d: addr=0x%"PRIx64
                                 " len=%u is_write=%d mr=%d data=0x%08x",
                                 non_uart_count, mmio_addr,
                                 run->mmio.len, run->mmio.is_write,
                                 (int)mr, val);
                }
                non_uart_count++;
            }
            break;
        }

        case GH_VCPU_EXIT_STATUS:
            exit_status = run->status.status;
            exit_type = run->status.exit_info.type;
            qatomic_set(&gunyah_vm_stopped, true);

            /*
             * These shutdown/reset/panic request functions are
             * thread-safe and do NOT require BQL.  Calling them
             * without BQL avoids deadlocking with the main loop.
             */
            switch (exit_status) {
            case GH_VM_STATUS_CRASHED:
                    error_report("GH: cpu %d: VM CRASHED", cpu->cpu_index);
                    /* guest_panicked needs BQL for vm_stop */
                    cpu_exec_end(cpu);
                    bql_lock();
                    qemu_system_guest_panicked(NULL);
                    bql_unlock();
                    cpu_exec_start(cpu);
                    ret = EXCP_INTERRUPT;
                    break;
            case GH_VM_STATUS_EXITED:
                /* Fall-through */
            default:
                switch (exit_type) {
                case GH_RM_EXIT_TYPE_WDT_BITE:
                    error_report("GH: cpu %d: WDT BITE", cpu->cpu_index);
                    cpu_exec_end(cpu);
                    bql_lock();
                    qemu_system_guest_panicked(NULL);
                    bql_unlock();
                    cpu_exec_start(cpu);
                    ret = EXCP_INTERRUPT;
                    break;

                case GH_RM_EXIT_TYPE_PSCI_SYSTEM_RESET:
                case GH_RM_EXIT_TYPE_PSCI_SYSTEM_RESET2:
                    error_report("GH: cpu %d: PSCI SYSTEM_RESET — "
                                 "Gunyah VMs cannot reset (LEND'd memory "
                                 "is host-inaccessible), shutting down",
                                 cpu->cpu_index);
                    /*
                     * Gunyah protected VMs cannot be reset because the
                     * host has no access to LEND'd memory after VM_START.
                     * A reset would require QEMU to re-load the kernel,
                     * DTB, and boot stub — all of which reside in LEND'd
                     * memory — causing a SIGBUS crash.
                     *
                     * Force-exit like POWER_OFF. The main event loop
                     * may not pump on Android, so _exit() is safest.
                     * The wrapper/user can restart QEMU if needed.
                     */
                    _exit(0);
                case GH_RM_EXIT_TYPE_VM_EXIT:
                case GH_RM_EXIT_TYPE_PSCI_POWER_OFF:
                    /* Fall-through */
                default:
                    error_report("GH: cpu %d: PSCI POWER_OFF / VM_EXIT "
                                 "(exit_type=%d) — exiting",
                                 cpu->cpu_index, exit_type);
                    /*
                     * Force-exit the process.  The normal path
                     * (qemu_system_shutdown_request → main loop →
                     * exit) doesn't work reliably in the Android
                     * library build because the main event loop
                     * may not be pumped by the wrapper app.
                     * _exit() is safe here: the guest has already
                     * shut down, so there's nothing left to clean up.
                     */
                    _exit(0);
                }
            }
            break;

        case GH_VCPU_EXIT_PAGE_FAULT:
            /*
             * PAGE_FAULT exit: the kernel's demand paging couldn't
             * resolve a stage-2 fault and forwarded it to userspace.
             *
             * The kernel populates run->page_fault with:
             *   .phys_addr    - faulting guest physical address
             *   .attempt      - error code from gunyah_demand_page()
             *                   (e.g. -ENOENT, -EPERM, -EIO, etc.)
             *   .resume_action - initially GUNYAH_VCPU_RESUME_FAULT
             *
             * We can set resume_action to tell the kernel what to do
             * on the next GH_VCPU_RUN:
             *   RESUME_RETRY  - retry the faulting instruction
             *   RESUME_FAULT  - inject data abort into guest
             */
            {
                uint64_t fault_addr = run->page_fault.phys_addr;
                int32_t attempt = run->page_fault.attempt;
                AccelCPUState *acpu = cpu->accel;

                if (fault_addr == acpu->last_fault_addr) {
                    acpu->same_fault_count++;
                } else {
                    acpu->last_fault_addr = fault_addr;
                    acpu->same_fault_count = 1;
                }

                if (acpu->same_fault_count == 1) {
                    static int page_fault_log_count;
                    if (page_fault_log_count < 100) {
                        error_report("GH: CPU#%d PAGE_FAULT at "
                            "0x%"PRIx64" attempt=%d (%s) lend=%d",
                            cpu->cpu_index, fault_addr, attempt,
                            attempt == -2 ? "ENOENT" :
                            attempt == -1 ? "EPERM" :
                            attempt == -5 ? "EIO" :
                            attempt == -12 ? "ENOMEM" :
                            attempt == -95 ? "EOPNOTSUPP" : "other",
                            gunyah_addr_is_lend(fault_addr));
                        page_fault_log_count++;
                    }
                }

                if (qatomic_read(&cpu->exit_request) ||
                    qatomic_read(&gunyah_vm_stopped)) {
                    ret = EXCP_INTERRUPT;
                    break;
                }

                /*
                 * PAGE_FAULT retry strategy:
                 *
                 * ENOMEM (-12) means the hypervisor's stage-2 page table
                 * pool is exhausted.  This is PERMANENT — nothing in
                 * userspace can free hypervisor page table entries.
                 * The root cause is too many demand-paged 4KB entries
                 * consuming the fixed-size pool.
                 *
                 * Give a brief retry window (a few attempts) in case of
                 * transient races, then inject fault quickly.  The guest
                 * kernel will receive a synchronous data abort (SIGBUS).
                 *
                 * Other errors: 10 retries with 1ms sleep, then give up.
                 */
                {
                    int max_retries = (attempt == -12) ? 10 : 10;

                    if (acpu->same_fault_count <= max_retries) {
                        /* Retry: fault may be transient */
                        run->page_fault.resume_action = GH_VCPU_RESUME_RETRY;
                        if (acpu->same_fault_count > 3) {
                            usleep(1000); /* 1ms */
                        }
                        ret = 0;
                    } else {
                        /*
                         * Permanent failure — inject fault into guest.
                         * Use RESUME_FAULT so the hypervisor delivers a
                         * synchronous external abort to the guest.
                         */
                        if (acpu->same_fault_count == max_retries + 1) {
                            error_report("GH: CPU#%d PAGE_FAULT at 0x%"PRIx64
                                " PERMANENT (attempt=%d) after %d retries"
                                " — injecting abort into guest",
                                cpu->cpu_index, fault_addr, attempt,
                                acpu->same_fault_count);
                        }
                        run->page_fault.resume_action = GH_VCPU_RESUME_FAULT;
                        /*
                         * Sleep 50ms to give guest exception handler
                         * time to run (handle the abort, SIGBUS the
                         * faulting process) before we re-enter.
                         */
                        usleep(50000);
                        ret = 0;
                    }
                }
            }
            break;

        default:
            /*
             * Unknown/extended exit reason.
             *
             * For non-LEND addresses with a valid MMIO payload
             * (len 1-8), dispatch normally via address_space_rw.
             * For LEND'd addresses or unknown exits, retry briefly
             * then give up.
             */
            {
                uint64_t unk_addr = run->mmio.phys_addr;
                AccelCPUState *acpu = cpu->accel;

                if (!gunyah_addr_is_lend(unk_addr) &&
                    run->mmio.len > 0 && run->mmio.len <= 8) {
                    bql_lock();
                    address_space_rw(&address_space_memory,
                        unk_addr, MEMTXATTRS_UNSPECIFIED,
                        run->mmio.data, run->mmio.len,
                        run->mmio.is_write);
                    bql_unlock();
                    ret = 0;
                } else {
                    if (unk_addr == acpu->last_fault_addr) {
                        acpu->same_fault_count++;
                    } else {
                        acpu->last_fault_addr = unk_addr;
                        acpu->same_fault_count = 1;
                    }

                    if (acpu->same_fault_count > 500) {
                        error_report("GH: CPU#%d exit_reason=%d stuck "
                                     "at addr=0x%"PRIx64" (%d repeats)"
                                     " — unresolvable fault, aborting",
                                     cpu->cpu_index, exit_reason,
                                     unk_addr, acpu->same_fault_count);
                        ret = -1;
                    } else {
                        if (acpu->same_fault_count > 10) {
                            usleep(100);
                        }
                        ret = 0;
                    }
                }
            }
        }
    } while (ret == 0);

    cpu_exec_end(cpu);
    bql_lock();

    if (ret < 0) {
        cpu_dump_state(cpu, stderr, CPU_DUMP_CODE);
        vm_stop(RUN_STATE_INTERNAL_ERROR);
    }

    qatomic_set(&cpu->exit_request, 0);

    return ret;
}

void *gunyah_cpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;

    rcu_register_thread();

    bql_lock();
    qemu_thread_get_self(cpu->thread);

    cpu->thread_id = qemu_get_thread_id();
    current_cpu = cpu;

    error_report("GH: cpu_thread_fn started for cpu %d (tid=%d)",
                 cpu->cpu_index, cpu->thread_id);

    gunyah_init_vcpu(cpu, &error_fatal);

    /* signal CPU creation */
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    error_report("GH: cpu %d entering main loop (fd=%d run=%p)",
                 cpu->cpu_index, cpu->accel->fd, cpu->accel->run);

    do {
        if (cpu_can_run(cpu)) {
            gunyah_vcpu_exec(cpu);
        }
        qemu_wait_io_event(cpu);
    } while (!cpu->unplug || cpu_can_run(cpu));

    gunyah_vcpu_destroy(cpu);
    cpu_thread_signal_destroyed(cpu);
    bql_unlock();
    rcu_unregister_thread();
    return NULL;
}

static void do_gunyah_cpu_synchronize_post_reset(CPUState *cpu,
                                run_on_cpu_data arg)
{
    gunyah_arch_put_registers(cpu, 0);
    cpu->vcpu_dirty = false;
}

void gunyah_cpu_synchronize_post_reset(CPUState *cpu)
{
    run_on_cpu(cpu, do_gunyah_cpu_synchronize_post_reset, RUN_ON_CPU_NULL);
}
