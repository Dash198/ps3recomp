/*
 * ps3recomp - guest guard-page registry
 *
 * vm_protect() is the only place that removes read access from a range of the
 * flat guest arena; the PPU stack allocator uses it for the guard page below
 * every thread stack. A guest stack dump walks arbitrary words and therefore
 * must not assume that "inside ppu_vm_size" means "readable": the guard is
 * inside on purpose. Keep the small set of no-read ranges here so diagnostics
 * can skip them without installing a signal handler or catching faults.
 *
 * The table is fixed-size and lock-free. The only writer paths are thread
 * creation (one guard per stack) and shutdown/reset; readers are diagnostic
 * walkers, which may run from a faulting guest thread. A missed entry must
 * never mean a wild read, so a full table is reported once rather than
 * silently ignored.
 */

#include "vm.h"

#include <stdio.h>

#define VM_GUARD_SLOTS 256

/* Packed as (guest address << 32) | length. Zero means free. A range with
 * address 0 and a non-zero length still encodes as non-zero. */
static volatile uint64_t s_guard[VM_GUARD_SLOTS];

static uint64_t guard_pack(uint32_t addr, uint32_t size)
{
    return ((uint64_t)addr << 32) | (uint64_t)size;
}

static uint32_t guard_addr(uint64_t v)
{
    return (uint32_t)(v >> 32);
}

static uint32_t guard_size(uint64_t v)
{
    return (uint32_t)v;
}

void vm_guard_reset(void)
{
    for (int i = 0; i < VM_GUARD_SLOTS; i++)
        __atomic_store_n(&s_guard[i], 0, __ATOMIC_RELEASE);
}

void vm_guard_note(uint32_t addr, uint32_t size, int readable)
{
    if (size == 0)
        return;

    uint64_t a0 = addr;
    uint64_t a1 = (uint64_t)addr + size;

    if (readable) {
        /* Clear a guard entry only when the whole range is made readable.
         * Stack-guard callers always use exact pages; a partial clear would
         * require splitting an entry, and leaving it is the safe direction:
         * a diagnostic skips a page that is now readable, instead of reading
         * one that is still protected. */
        for (int i = 0; i < VM_GUARD_SLOTS; i++) {
            uint64_t v = __atomic_load_n(&s_guard[i], __ATOMIC_ACQUIRE);
            if (!v)
                continue;
            uint64_t s0 = guard_addr(v);
            uint64_t s1 = s0 + guard_size(v);
            if (a0 <= s0 && a1 >= s1) {
                uint64_t expected = v;
                __atomic_compare_exchange_n(&s_guard[i], &expected, 0, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            }
        }
        return;
    }

    uint64_t packed = guard_pack(addr, size);

    /* Duplicate notes are harmless and common while a thread is being set up. */
    for (int i = 0; i < VM_GUARD_SLOTS; i++) {
        if (__atomic_load_n(&s_guard[i], __ATOMIC_ACQUIRE) == packed)
            return;
    }

    for (int i = 0; i < VM_GUARD_SLOTS; i++) {
        uint64_t expected = 0;
        if (__atomic_compare_exchange_n(&s_guard[i], &expected, packed, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return;
    }

    {
        static int reported = 0;
        if (!reported) {
            reported = 1;
            fprintf(stderr, "[vm] guard table full (%d ranges); a stack-dump "
                            "probe may fault\n", VM_GUARD_SLOTS);
        }
    }
}

int vm_guest_range_readable(uint32_t addr, uint32_t size)
{
    if (size == 0)
        return 1;
    if (!VM_READY)
        return 0;

    /* The flat POSIX arena stops at ppu_vm_size. Windows reserves the whole
     * 32-bit space plus a guard and sets ppu_vm_size to 0 because the vectored
     * fault handler backs touched pages. */
    if (ppu_vm_size != 0 && (uint64_t)addr + size > (uint64_t)ppu_vm_size)
        return 0;

    uint64_t a0 = addr;
    uint64_t a1 = (uint64_t)addr + size;
    for (int i = 0; i < VM_GUARD_SLOTS; i++) {
        uint64_t v = __atomic_load_n(&s_guard[i], __ATOMIC_ACQUIRE);
        if (!v)
            continue;
        uint64_t s0 = guard_addr(v);
        uint64_t s1 = s0 + guard_size(v);
        if (a0 < s1 && s0 < a1)
            return 0;
    }
    return 1;
}
