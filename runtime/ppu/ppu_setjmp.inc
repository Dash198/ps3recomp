/* Guest setjmp / longjmp machinery -- textually included by ppu_loader.cpp.
 *
 * It is split out so the conformance harness (tools/test_ppu_setjmp_exec.py)
 * can compile and RUN this exact code against a stub VM. The alternative -- a
 * hand-copied stand-in for the runtime -- tests the copy, not the runtime, and
 * drifts silently the first time either side changes.
 *
 * The includer must already have in scope:
 *     ppu_context, jmp_buf (<setjmp.h>), PPU_THREAD_LOCAL
 *     uint64_t vm_read64(uint64_t)        -- the guest memory read
 *     int g_vcall_sp, g_vcall_depth       -- vcall bookkeeping, restored on jump
 *     void (*g_trampoline_fn)(void*)      -- cleared on jump
 * ppu_loader.cpp defines every one of them above the include point; the test
 * harness defines minimal stand-ins for the same names.
 */
/* ---------------------------------------------------------------------------
 * Guest setjmp / longjmp.
 *
 * A call to the SDK's statically linked libgcc context-save helper
 * (__savegprlr_14) IS the guest's setjmp; the restore helper
 * (__restgprlr_14) reloads the whole non-volatile context and then does `blr`
 * to the LR it reloaded -- a NON-LOCAL jump. ppu_lifter recognises both by
 * shape and emits PPU_SETJMP_GUARD at every save call site, so the setjmp
 * landing pad lives in the guest function's own frame (which stays live across
 * the callback that eventually longjmps -- the helper's own frame does not),
 * and ppu_lj_do() at the end of the restore helper's body.
 *
 * Same shape as the SPU side's spu_halt -> longjmp (spu_channels.c), and the
 * same reason it is sound: the jump target is always SHALLOWER in the same host
 * thread, so the host frames the longjmp discards are exactly the guest frames
 * the `blr` discards. The save helper then returns to its guest call site --
 * which IS the reloaded LR -- leaving r3 as the longjmp value.
 * -------------------------------------------------------------------------*/
typedef struct {
    uint32_t blk;        /* aligned guest context block (0 == never armed) */
    jmp_buf  env;
    int      vcsp;       /* g_vcall_sp    when armed */
    int      vcdepth;    /* g_vcall_depth when armed */
} ppu_sj_slot_t;
#define PPU_SJ_SLOTS 256
static PPU_THREAD_LOCAL ppu_sj_slot_t g_sj_slots[PPU_SJ_SLOTS];
static PPU_THREAD_LOCAL uint32_t     g_sj_nslots = 0;
static PPU_THREAD_LOCAL uint32_t     g_sj_evict  = 0;

static int ppu_sj_trace(void)
{
    static int on = -1;
    if (on < 0) on = getenv("PS3_SJ_TRACE") ? 1 : 0;
    return on;
}

/* Arm (or re-arm) the pad for a guest block and hand back its host jmp_buf. The
 * caller -- the generated PPU_SETJMP_GUARD -- runs setjmp on it in its own
 * frame, then calls the save helper. */
extern "C" jmp_buf* ppu_sj_slot(ppu_context* ctx, uint64_t blk)
{
    const uint32_t b = (uint32_t)blk;
    ppu_sj_slot_t* s = nullptr;
    for (uint32_t i = 0; i < g_sj_nslots; i++)
        if (g_sj_slots[i].blk == b) { s = &g_sj_slots[i]; break; }
    if (!s) {
        if (g_sj_nslots < PPU_SJ_SLOTS) {
            s = &g_sj_slots[g_sj_nslots++];
        } else {
            /* A long-lived title arms more distinct blocks than the table holds
             * (every object carries its own). Recycle round-robin: only the most
             * recent arming of a block is live anyway, and a block we no longer
             * hold is refused by ppu_lj_do rather than jumped to. */
            s = &g_sj_slots[g_sj_evict++ % PPU_SJ_SLOTS];
            if ((g_sj_evict & 0xFF) == 1)
                fprintf(stderr, "[ppu] setjmp slot table full (%d); recycling "
                                "oldest arms\n", (int)PPU_SJ_SLOTS);
        }
        s->blk = b;
    }
    /* A longjmp unwinds past the matching decrements of these counters, so
     * remember the values the unwound frames would have restored. */
    s->vcsp = g_vcall_sp;
    s->vcdepth = g_vcall_depth;
    if (ppu_sj_trace()) {
        static int _n = 0;
        if (_n++ < 40)
            fprintf(stderr, "[sj] arm  blk=0x%08X sp=0x%08X tid=%llu\n", b,
                    (uint32_t)ctx->gpr[1], (unsigned long long)ctx->thread_id);
    }
    return &s->env;
}

/* The restore helper's longjmp. blk is the aligned context block; cur_sp is the
 * guest r1 captured before the helper overwrote it (the block's own r1 load is
 * the SETJMP-time sp). A target that is not an ancestor of the current frame is
 * refused, leaving the restored context in place and returning -- the pre-fix
 * behaviour -- rather than jumping into a dead host frame. */
extern "C" void ppu_lj_do(ppu_context* ctx, uint64_t blk, uint64_t cur_sp)
{
    const uint32_t b = (uint32_t)blk;
    const uint64_t saved_sp = vm_read64(b + 0x0);   /* block[0] = setjmp-time r1 */
    for (uint32_t i = 0; i < g_sj_nslots; i++) {
        ppu_sj_slot_t* s = &g_sj_slots[i];
        if (s->blk != b) continue;
        if (saved_sp < cur_sp) {
            static int _n = 0;
            if (_n++ < 8)
                fprintf(stderr, "[ppu] longjmp blk=0x%08X refused: saved sp "
                                "0x%08X < current 0x%08X (setjmp frame not live)\n",
                        b, (uint32_t)saved_sp, (uint32_t)cur_sp);
            return;
        }
        if (ppu_sj_trace()) {
            static int _n = 0;
            if (_n++ < 40)
                fprintf(stderr, "[sj] jump blk=0x%08X saved_sp=0x%08X cur_sp=0x%08X "
                                "r3=0x%08X tid=%llu\n", b, (uint32_t)saved_sp,
                        (uint32_t)cur_sp, (uint32_t)ctx->gpr[3],
                        (unsigned long long)ctx->thread_id);
        }
        g_vcall_sp = s->vcsp;
        g_vcall_depth = s->vcdepth;
        g_trampoline_fn = nullptr;
        longjmp(s->env, 1);
    }
    static int _n = 0;
    if (_n++ < 8)
        fprintf(stderr, "[ppu] longjmp blk=0x%08X with no armed setjmp "
                        "(saved sp 0x%08X, current 0x%08X)\n",
                b, (uint32_t)saved_sp, (uint32_t)cur_sp);
}
