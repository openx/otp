/*
 * %CopyrightBegin%
 *
 * Copyright Ericsson AB 1996-2017. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * %CopyrightEnd%
 */

/* Conversion to JSON format.
 *
 * This code is derived from the external term format conversion code in
 * external.c, and reuses some of the data structures defined by that code,
 * notably TTBEncode.  ETF construction has three phases (determining the
 * binary size, encoding, and compressing) but JSON construction does not have
 * compression, and grows the output binary as necessary instead of making a
 * separate pass over the input first to calculate the size.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#define ERTS_WANT_EXTERNAL_TAGS

#include "sys.h"
#include "erl_vm.h"
#include "global.h"
#include "erl_process.h"
#include "error.h"
#include "external.h"
#define ERL_WANT_HIPE_BIF_WRAPPER__
#include "bif.h"
#undef ERL_WANT_HIPE_BIF_WRAPPER__
#include "big.h"
#include "dist.h"
#include "erl_binary.h"
#include "erl_bits.h"
#include "erl_zlib.h"
#include "erl_map.h"

static Export term_to_json_trap_export;

static byte* enc_json(Eterm, byte*, Uint32, struct erl_off_heap_header** off_heap);
struct TTBEncodeContext_;
static int enc_json_int(struct TTBEncodeContext_*, Eterm obj, byte* ep, Uint32 dflags,
                        struct erl_off_heap_header** off_heap, Sint *reds, byte **res);
struct J2TContext_t;
static byte* dec_json(ErtsDistExternal*, ErtsHeapFactory*, byte*, Eterm*, struct J2TContext_t*);
static Sint decoded_size(byte *ep, byte* endp, int internal_tags, struct J2TContext_t*);
static BIF_RETTYPE term_to_json_trap_1(BIF_ALIST_1);

static Eterm erts_term_to_json_int(Process* p, Eterm Term, Uint flags, Binary *context_b);

static Export json_to_term_trap_export;
static BIF_RETTYPE json_to_term_trap_1(BIF_ALIST_1);
static BIF_RETTYPE json_to_term_int(Process* p, Uint32 flags, Eterm bin, Binary* context_b,
                                    Export *bif, Eterm arg0, Eterm arg1);

void erts_init_json(void) {
    erts_init_trap_export(&term_to_json_trap_export,
                          am_erts_internal, am_term_to_json_trap, 1,
                          &term_to_json_trap_1);

    erts_init_trap_export(&json_to_term_trap_export,
                          am_erts_internal, am_json_to_term_trap, 1,
                          &json_to_term_trap_1);
    return;
}

/**********************************************************************/

static BIF_RETTYPE term_to_json_trap_1(BIF_ALIST_1)
{
    Eterm *tp = tuple_val(BIF_ARG_1);
    Eterm Term = tp[1];
    Eterm bt = tp[2];
    Binary *bin = erts_magic_ref2bin(bt);
    Eterm res = erts_term_to_json_int(BIF_P, Term, 0, bin);
    if (is_tuple(res)) {
        ASSERT(BIF_P->flags & F_DISABLE_GC);
        BIF_TRAP1(&term_to_json_trap_export, BIF_P, res);
    } else {
        if (erts_set_gc_state(BIF_P, 1)
            || MSO(BIF_P).overhead > BIN_VHEAP_SZ(BIF_P))
            ERTS_BIF_YIELD_RETURN(BIF_P, res);
        else
            BIF_RET(res);
    }
}

HIPE_WRAPPER_BIF_DISABLE_GC(term_to_json, 1)

/* erlang:term_to_json/1 entry point. */
BIF_RETTYPE term_to_json_1(BIF_ALIST_1)
{
    Eterm res = erts_term_to_json_int(BIF_P, BIF_ARG_1, TERM_TO_JSON_DFLAGS, NULL);
    if (is_tuple(res)) {
        erts_set_gc_state(BIF_P, 0);
        BIF_TRAP1(&term_to_json_trap_export, BIF_P, res);
    } else {
        ASSERT(!(BIF_P->flags & F_DISABLE_GC));
        BIF_RET(res);
    }
}

#if 0
HIPE_WRAPPER_BIF_DISABLE_GC(term_to_json, 2)

/* erlang:term_to_json/2 entry point. */
BIF_RETTYPE term_to_json_2(BIF_ALIST_2)
{
    Process* p = BIF_P;
    Eterm Term = BIF_ARG_1;
    Eterm Flags = BIF_ARG_2;
    Uint flags = TERM_TO_JSON_DFLAGS;
    Eterm res;

    while (is_list(Flags)) {
        Eterm arg = CAR(list_val(Flags));
        Eterm* tp;
        if (is_tuple(arg) && *(tp = tuple_val(arg)) == make_arityval(2)) {
            if (tp[1] == am_minor_version && is_small(tp[2])) {
                switch (signed_val(tp[2])) {
                case 0:
                    flags = TERM_TO_JSON_DFLAGS & ~DFLAG_NEW_FLOATS;
                    break;
                case 1: /* Current default... */
                    flags = TERM_TO_JSON_DFLAGS;
                    break;
                case 2:
                    flags = TERM_TO_JSON_DFLAGS | DFLAG_UTF8_ATOMS;
                    break;
                default:
                    goto error;
                }
            } else {
                goto error;
            }
        } else {
        error:
            BIF_ERROR(p, BADARG);
        }
        Flags = CDR(list_val(Flags));
    }
    if (is_not_nil(Flags)) {
        goto error;
    }

    res = erts_term_to_json_int(p, Term, flags, NULL);
    if (is_tuple(res)) {
        erts_set_gc_state(p, 0);
        BIF_TRAP1(&term_to_json_trap_export,BIF_P,res);
    } else {
        ASSERT(!(BIF_P->flags & F_DISABLE_GC));
        BIF_RET(res);
    }
}
#endif


static BJTContext* j2t_export_context(Process* p, J2TContext* src)
{
    Binary* context_b = erts_create_magic_binary(sizeof(J2TContext),
                                                 j2t_context_destructor);
    J2TContext* ctx = ERTS_MAGIC_BIN_DATA(context_b);
    Eterm* hp;
    sys_memcpy(ctx, src, sizeof(J2TContext));
    if (ctx->state >= J2TDecode && ctx->u.dc.next == &src->u.dc.res) {
        ctx->u.dc.next = &ctx->u.dc.res;
    }
    hp = HAlloc(p, ERTS_MAGIC_REF_THING_SIZE);
    ctx->trap_bin = erts_mk_magic_ref(&hp, &MSO(p), context_b);
    return ctx;
}

static BIF_RETTYPE json_to_term_int(Process* p, Uint32 flags, Eterm bin, Binary* context_b,
                                    Export *bif_init, Eterm arg0, Eterm arg1)
{
    BIF_RETTYPE ret_val;
#ifdef EXTREME_J2T_TRAPPING
    SWord initial_reds = 1 + j2t_rand() % 4;
#else
    SWord initial_reds = (Uint)(ERTS_BIF_REDS_LEFT(p) * J2T_BYTES_PER_REDUCTION);
#endif
    J2TContext c_buff;
    J2TContext *ctx;
    int is_first_call;

    if (context_b == NULL) {
        /* Setup enough to get started */
        is_first_call = 1;
        ctx = &c_buff;
        ctx->state = J2TPrepare;
        ctx->aligned_alloc = NULL;
        ctx->flags = flags;
        ctx->bif = bif_init;
        ctx->arg[0] = arg0;
        ctx->arg[1] = arg1;
        IF_DEBUG(ctx->trap_bin = THE_NON_VALUE;)
    } else {
        is_first_call = 0;
        ctx = ERTS_MAGIC_BIN_DATA(context_b);
        ASSERT(ctx->state != J2TPrepare);
    }
    ctx->reds = initial_reds;

    do {
        switch (ctx->state) {
        case J2TPrepare: {
            byte* bytes;
            Uint bin_size;
            bytes = erts_get_aligned_binary_bytes_extra(bin,
                                                        &ctx->aligned_alloc,
                                                        ERTS_ALC_T_EXT_TERM_DATA,
                                                        0);
            if (bytes == NULL) {
                ctx->j2ts.exttmp = 0;
                ctx->state = J2TBadArg;
                break;
            }
            bin_size = binary_size(bin);
            if (ctx->aligned_alloc) {
                ctx->reds -= bin_size / 8;
            }
            if (binary2term_prepare(&ctx->j2ts, bytes, bin_size, &ctx, p) < 0) {
                ctx->state = J2TBadArg;
            }
            break;
        }
        case J2TUncompressChunk: {
            uLongf chunk = ctx->reds;
            int zret;

            if (chunk > ctx->u.uc.dleft)
                chunk = ctx->u.uc.dleft;
            zret = erl_zlib_inflate_chunk(&ctx->u.uc.stream,
                                          ctx->u.uc.dbytes, &chunk);
            ctx->u.uc.dbytes += chunk;
            ctx->u.uc.dleft  -= chunk;
            if (zret == Z_OK && ctx->u.uc.dleft > 0) {
                ctx->reds = 0;
            }
            else if (erl_zlib_inflate_finish(&ctx->u.uc.stream) == Z_OK
                     && zret == Z_STREAM_END
                     && ctx->u.uc.dleft == 0) {
                ctx->reds -= chunk;
                ctx->state = J2TSizeInit;
            }
            else {
                ctx->state = J2TBadArg;
            }
            break;
        }
        case J2TSizeInit:
            ctx->u.sc.ep = NULL;
            ctx->state = J2TSize;
            /*fall through*/
        case J2TSize:
            ctx->heap_size = decoded_size(ctx->j2ts.extp,
                                          ctx->j2ts.extp + ctx->j2ts.extsize,
                                          0, ctx);
            break;

        case J2TDecodeInit:
            if (ctx == &c_buff && ctx->j2ts.extsize > ctx->reds) {
                /* dec_json will maybe trap, allocate space for magic bin
                   before result term to make it easy to trim with HRelease.
                 */
                ctx = j2t_export_context(p, &c_buff);
            }
            ctx->u.dc.ep = ctx->j2ts.extp;
            ctx->u.dc.res = (Eterm) (UWord) NULL;
            ctx->u.dc.next = &ctx->u.dc.res;
            erts_factory_proc_prealloc_init(&ctx->u.dc.factory, p, ctx->heap_size);
            ctx->u.dc.flat_maps.wstart = NULL;
            ctx->u.dc.hamt_array.pstart = NULL;
            ctx->state = J2TDecode;
            /*fall through*/
        case J2TDecode:
        case J2TDecodeList:
        case J2TDecodeTuple:
        case J2TDecodeString:
        case J2TDecodeBinary: {
            ErtsDistExternal fakedep;
            fakedep.flags = ctx->flags;
            dec_json(&fakedep, NULL, NULL, NULL, ctx);
            break;
        }
        case J2TDecodeFail:
            /*fall through*/
        case J2TBadArg:
            BUMP_REDS(p, (initial_reds - ctx->reds) / J2T_BYTES_PER_REDUCTION);

            ASSERT(ctx->bif == bif_export[BIF_json_to_term_1]
                   || ctx->bif == bif_export[BIF_json_to_term_2]);

            if (is_first_call)
                ERTS_BIF_PREP_ERROR(ret_val, p, BADARG);
            else {
                erts_set_gc_state(p, 1);
                if (is_non_value(ctx->arg[1]))
                    ERTS_BIF_PREP_ERROR_TRAPPED1(ret_val, p, BADARG, ctx->bif,
                                                 ctx->arg[0]);
                else
                    ERTS_BIF_PREP_ERROR_TRAPPED2(ret_val, p, BADARG, ctx->bif,
                                                 ctx->arg[0], ctx->arg[1]);
            }
            j2t_destroy_context(ctx);
            return ret_val;

        case J2TDone:
            j2t_destroy_context(ctx);

            if (ctx->u.dc.factory.hp > ctx->u.dc.factory.hp_end) {
                erts_exit(ERTS_ERROR_EXIT, ":%s, line %d: heap overrun by %d words(s)\n",
                         __FILE__, __LINE__, ctx->u.dc.factory.hp - ctx->u.dc.factory.hp_end);
            }
            erts_factory_close(&ctx->u.dc.factory);

            if (!is_first_call) {
                erts_set_gc_state(p, 1);
            }
            BUMP_REDS(p, (initial_reds - ctx->reds) / J2T_BYTES_PER_REDUCTION);
            ERTS_BIF_PREP_RET(ret_val, ctx->u.dc.res);
            return ret_val;

        default:
            ASSERT(!"Unknown state in json_to_term");
        }
    }while (ctx->reds > 0 || ctx->state >= J2TDone);

    if (ctx == &c_buff) {
        ASSERT(ctx->trap_bin == THE_NON_VALUE);
        ctx = j2t_export_context(p, &c_buff);
    }
    ASSERT(ctx->trap_bin != THE_NON_VALUE);

    if (is_first_call) {
        erts_set_gc_state(p, 0);
    }
    BUMP_ALL_REDS(p);

    ERTS_BIF_PREP_TRAP1(ret_val, &json_to_term_trap_export,
                        p, ctx->trap_bin);

    return ret_val;
}

HIPE_WRAPPER_BIF_DISABLE_GC(json_to_term, 1)

BIF_RETTYPE json_to_term_1(BIF_ALIST_1)
{
    return json_to_term_int(BIF_P, 0, BIF_ARG_1, NULL, bif_export[BIF_json_to_term_1],
                            BIF_ARG_1, THE_NON_VALUE);
}

HIPE_WRAPPER_BIF_DISABLE_GC(json_to_term, 2)

BIF_RETTYPE json_to_term_2(BIF_ALIST_2)
{
    Eterm opts;
    Eterm opt;
    Uint32 flags = 0;

    opts = BIF_ARG_2;
    while (is_list(opts)) {
        opt = CAR(list_val(opts));
        if (opt == am_safe) {
            flags |= ERTS_DIST_EXT_BTT_SAFE;
        }
        else {
            goto error;
        }
        opts = CDR(list_val(opts));
    }

    if (is_not_nil(opts))
        goto error;

    return json_to_term_int(BIF_P, flags, BIF_ARG_1, NULL, bif_export[BIF_json_to_term_2],
                            BIF_ARG_1, BIF_ARG_2);

error:
    BIF_ERROR(BIF_P, BADARG);
}

static Eterm
erts_term_to_json_simple(Process* p, Eterm Term, Uint size, Uint flags)
{
    Eterm bin;
    size_t real_size;
    byte* endp;
    byte* bytes;

    bin = new_binary(p, (byte *)NULL, size);
    bytes = binary_bytes(bin);
    bytes[0] = VERSION_MAGIC;
    if ((endp = enc_json(NULL, Term, bytes+1, flags, NULL))
        == NULL) {
        erts_exit(ERTS_ERROR_EXIT, "%s, line %d: bad term: %x\n",
                  __FILE__, __LINE__, Term);
    }
    real_size = endp - bytes;
    if (real_size > size) {
        erts_exit(ERTS_ERROR_EXIT, "%s, line %d: buffer overflow: %d word(s)\n",
                  __FILE__, __LINE__, endp - (bytes + size));
    }
    return erts_realloc_binary(bin, real_size);
}

Eterm
erts_term_to_json(Process* p, Eterm Term, Uint flags) {
    Uint size;
    size = encode_size_struct2(NULL, Term, flags) + 1 /* VERSION_MAGIC */;
    return erts_term_to_json_simple(p, Term, size, flags);
}

/* Define EXTREME_TTB_TRAPPING for testing in dist.h */

#ifndef EXTREME_TTB_TRAPPING
#define TERM_TO_JSON_COMPRESS_CHUNK (1 << 18)
#else
#define TERM_TO_JSON_COMPRESS_CHUNK 10
#endif
#define TERM_TO_JSON_MEMCPY_FACTOR 8

static int ttb_context_destructor(Binary *context_bin)
{
    TTBContext *context = ERTS_MAGIC_BIN_DATA(context_bin);
    if (context->alive) {
        context->alive = 0;
        switch (context->state) {
        case TTBSize:
            DESTROY_SAVED_WSTACK(&context->s.sc.wstack);
            break;
        case TTBEncode:
            DESTROY_SAVED_WSTACK(&context->s.ec.wstack);
            if (context->s.ec.result_bin != NULL) { /* Set to NULL if ever made alive! */
                ASSERT(erts_refc_read(&(context->s.ec.result_bin->intern.refc),1));
                erts_bin_free(context->s.ec.result_bin);
                context->s.ec.result_bin = NULL;
            }
            break;
        case TTBCompress:
            erl_zlib_deflate_finish(&(context->s.cc.stream));

            if (context->s.cc.destination_bin != NULL) { /* Set to NULL if ever made alive! */
                ASSERT(erts_refc_read(&(context->s.cc.destination_bin->intern.refc),1));
                erts_bin_free(context->s.cc.destination_bin);
                context->s.cc.destination_bin = NULL;
            }

            if (context->s.cc.result_bin != NULL) { /* Set to NULL if ever made alive! */
                ASSERT(erts_refc_read(&(context->s.cc.result_bin->intern.refc),1));
                erts_bin_free(context->s.cc.result_bin);
                context->s.cc.result_bin = NULL;
            }
            break;
        }
    }
    return 1;
}

static Eterm erts_term_to_json_int(Process* p, Eterm Term, Uint flags, Binary *context_b)
{
    Eterm *hp;
    Eterm res;
    Eterm c_term;
#ifndef EXTREME_TTB_TRAPPING
    Sint reds = (Sint) (ERTS_BIF_REDS_LEFT(p) * TERM_TO_JSON_LOOP_FACTOR);
#else
    Sint reds = 20; /* For testing */
#endif
    Sint initial_reds = reds;
    TTBContext c_buff;
    TTBContext *context = &c_buff;


#define EXPORT_CONTEXT()						\
    do {								\
        if (context_b == NULL) {					\
            context_b = erts_create_magic_binary(sizeof(TTBContext),    \
                                                 ttb_context_destructor);   \
            context =  ERTS_MAGIC_BIN_DATA(context_b);			\
            memcpy(context, &c_buff, sizeof(TTBContext));		\
        }								\
    } while (0)

#define RETURN_STATE()							\
    do {								\
        hp = HAlloc(p, ERTS_MAGIC_REF_THING_SIZE+3);                    \
        c_term = erts_mk_magic_ref(&hp, &MSO(p), context_b);            \
        res = TUPLE2(hp, Term, c_term);					\
        BUMP_ALL_REDS(p);                                               \
        return res;							\
    } while (0)


    if (context_b == NULL) {
        /* Setup enough to get started */
        context->state = TTBSize;
        context->alive = 1;
        context->s.sc.wstack.wstart = NULL;
        context->s.sc.flags = flags;
    } else {
        context = ERTS_MAGIC_BIN_DATA(context_b);
    }

    byte *endp;
    byte *bytes = (byte *) context->s.ec.result_bin->orig_bytes;
    size_t real_size;
    Binary *result_bin;

    flags = context->s.ec.flags;
    if (enc_json_int(&context->s.ec, NULL, Term, bytes+1, flags, NULL, &reds, &endp) < 0) {
        EXPORT_CONTEXT();
        RETURN_STATE();
    }
    real_size = endp - bytes;
    result_bin = erts_bin_realloc(context->s.ec.result_bin, real_size);
    BUMP_REDS(p, (initial_reds - reds) / TERM_TO_JSON_LOOP_FACTOR);
    ProcBin* pb;
    context->s.ec.result_bin = NULL;
    context->alive = 0;
    pb = (ProcBin *) HAlloc(p, PROC_BIN_SIZE);
    pb->thing_word = HEADER_PROC_BIN;
    pb->size = real_size;
    pb->next = MSO(p).first;
    MSO(p).first = (struct erl_off_heap_header*)pb;
    pb->val = result_bin;
    pb->bytes = (byte*) result_bin->orig_bytes;
    pb->flags = 0;
    OH_OVERHEAD(&(MSO(p)), pb->size / sizeof(Eterm));
    if (context_b && erts_refc_read(&context_b->intern.refc,0) == 0) {
        erts_bin_free(context_b);
    }
    return make_binary(pb);
#undef EXPORT_CONTEXT
#undef RETURN_STATE
}

#define ENC_TERM ((Eterm) 0)
#define ENC_ONE_CONS ((Eterm) 1)
#define ENC_PATCH_FUN_SIZE ((Eterm) 2)
#define ENC_BIN_COPY ((Eterm) 3)
#define ENC_MAP_PAIR ((Eterm) 4)
#define ENC_HASHMAP_NODE ((Eterm) 5)
#define ENC_LAST_ARRAY_ELEMENT ((Eterm) 6)

static byte*
enc_json(Eterm obj, byte* ep, Uint32 dflags,
         struct erl_off_heap_header** off_heap)
{
    byte *res;
    (void) enc_json_int(NULL, obj, ep, dflags, off_heap, NULL, &res);
    return res;
}

/* Interruptable JSON encoder.  Returns 0 when term is completely encoded, or
   -1 when out of reductions. */

static int
enc_json_int(TTBEncodeContext* ctx, Eterm obj, byte* ep, Uint32 dflags,
             struct erl_off_heap_header** off_heap, Sint *reds, byte **res)
{
    DECLARE_WSTACK(s);
    Uint n;
    Uint i;
    Uint j;
    Uint* ptr;
    Eterm val;
    FloatDef f;
    Sint r = 0;

    if (ctx) {
        WSTACK_CHANGE_ALLOCATOR(s, ERTS_ALC_T_SAVED_ESTACK);
        r = *reds;

        if (ctx->wstack.wstart) { /* restore saved stacks and byte pointer */
            WSTACK_RESTORE(s, &ctx->wstack);
            ep = ctx->ep;
            obj = ctx->obj;
            if (is_non_value(obj)) {
                goto outer_loop;
            }
        }
    }


#define ENSURE_BUFFER(n)
    do {
        if () {
        }
    } while (0)


    goto L_jump_start;

 outer_loop:
    while (!WSTACK_ISEMPTY(s)) {
        obj = WSTACK_POP(s);

        switch (val = WSTACK_POP(s)) {
        case ENC_TERM:
            break;
        case ENC_ONE_CONS:
        encode_one_cons:
            {
                Eterm* cons = list_val(obj);
                Eterm tl;

                obj = CAR(cons);
                tl = CDR(cons);
                ENSURE_BUFFER(1);
                if (is_list(tl)) {
                    *ep++ = ',',
                    WSTACK_PUSH2(s, ENC_ONE_CONS, tl);
                } else {
                    *ep++ = ']';
                    WSTACK_PUSH2(s, ENC_TERM, tl);
                }
            }
            break;
        case ENC_BIN_COPY: {
            Uint bits = (Uint)obj;
            Uint bitoffs = WSTACK_POP(s);
            byte* bytes = (byte*) WSTACK_POP(s);
            byte* dst = (byte*) WSTACK_POP(s);
            if (bits > r * (TERM_TO_JSON_MEMCPY_FACTOR * 8)) {
                Uint n = r * TERM_TO_JSON_MEMCPY_FACTOR;
                WSTACK_PUSH5(s, (UWord)(dst + n), (UWord)(bytes + n), bitoffs,
                             ENC_BIN_COPY, bits - 8*n);
                bits = 8*n;
                copy_binary_to_buffer(dst, 0, bytes, bitoffs, bits);
                obj = THE_NON_VALUE;
                r = 0; /* yield */
                break;
            } else {
                copy_binary_to_buffer(dst, 0, bytes, bitoffs, bits);
                r -= bits / (TERM_TO_JSON_MEMCPY_FACTOR * 8);
                goto outer_loop;
            }
        }
        case ENC_MAP_PAIR: {
            Uint pairs_left = obj;
            Eterm *vptr = (Eterm*) WSTACK_POP(s);
            Eterm *kptr = (Eterm*) WSTACK_POP(s);

            obj = *kptr;
            if (--pairs_left > 0) {
                WSTACK_PUSH4(s, (UWord)(kptr+1), (UWord)(vptr+1),
                             ENC_MAP_PAIR, pairs_left);
            }
            WSTACK_PUSH2(s, ENC_TERM, *vptr);
            break;
        }
        case ENC_HASHMAP_NODE:
            if (is_list(obj)) { /* leaf node [K|V] */
                ptr = list_val(obj);
                WSTACK_PUSH2(s, ENC_TERM, CDR(ptr));
                obj = CAR(ptr);
            }
            break;
        case ENC_LAST_ARRAY_ELEMENT:
            /* obj is the tuple */
            {
                Eterm* ptr = (Eterm *) obj;
                obj = *ptr;
            }
            break;
        default:		/* ENC_LAST_ARRAY_ELEMENT+1 and upwards */
            {
                Eterm* ptr = (Eterm *) obj;
                obj = *ptr++;
                WSTACK_PUSH2(s, val-1, (UWord)ptr);
            }
            break;
        }

    L_jump_start:

        if (ctx && --r <= 0) {
            *reds = 0;
            ctx->obj = obj;
            ctx->ep = ep;
            WSTACK_SAVE(s, &ctx->wstack);
            return -1;
        }

        switch(tag_val_def(obj)) {
        case NIL_DEF:
            ENSURE_BUFFER(2);
            *ep++ = '['; *ep++ = ']';
            break;

        case ATOM_DEF:
            switch (atom_type(ep)) {
                ATOM_TRUE:  ENSURE_BUFFER(4); *ep++ = 't'; *ep++ = 'r'; *ep++ = 'u'; *ep++ = 'e'; break;
                ATOM_FALSE: ENSURE_BUFFER(5); *ep++ = 'f'; *ep++ = 'a'; *ep++ = 'l'; *ep++ = 's'; *ep++ = 'e'; break;
                ATOM_NULL:  ENSURE_BUFFER(4); *ep++ = 'n'; *ep++ = 'u'; *ep++ = 'l'; *ep++ = 'l'; break;
                default:    goto fail;
            }
            break;

        case SMALL_DEF: {
            // Emit a small integer.
            Sint val = signed_val(obj);
            ENSURE_BUFFER(30); // 20 chars is enough for -(2^63)-1.
            ep += sprintf("%lld", (long long) val); // This could probably be made faster.
        }
            break;

        case BIG_DEF:
            // Emit a big integer.
            goto fail;
#if 0
            {
                int sign = big_sign(obj);
                n = big_bytes(obj);
                if (sizeof(Sint)==4 && n<=4) {
                    Uint dig = big_digit(obj,0);
                    Sint val = sign ? -dig : dig;
                    if ((val<0) == sign) {
                        *ep++ = INTEGER_EXT;
                        put_int32(val, ep);
                        ep += 4;
                        break;
                    }
                }
                if (n < 256) {
                    *ep++ = SMALL_BIG_EXT;
                    put_int8(n, ep);
                    ep += 1;
                }
                else {
                    *ep++ = LARGE_BIG_EXT;
                    put_int32(n, ep);
                    ep += 4;
                }
                *ep++ = sign;
                ep = big_to_bytes(obj, ep);
            }
            break;
#endif

        case LIST_DEF:
            ENSURE_BUFFER(1);
            *ep++ = '[';
            goto encode_one_cons;

        case TUPLE_DEF:
            ptr = tuple_val(obj);
            i = arityval(*ptr);
            ptr++;
            if (i <= 0xff) {
                *ep++ = SMALL_TUPLE_EXT;
                put_int8(i, ep);
                ep += 1;
            } else  {
                *ep++ = LARGE_TUPLE_EXT;
                put_int32(i, ep);
                ep += 4;
            }
            if (i > 0) {
                WSTACK_PUSH2(s, ENC_LAST_ARRAY_ELEMENT+i-1, (UWord)ptr);
            }
            break;

        case MAP_DEF:
            if (is_flatmap(obj)) {
                flatmap_t *mp = (flatmap_t*)flatmap_val(obj);
                Uint size = flatmap_get_size(mp);

                *ep++ = MAP_EXT;
                put_int32(size, ep); ep += 4;

                if (size > 0) {
                    Eterm *kptr = flatmap_get_keys(mp);
                    Eterm *vptr = flatmap_get_values(mp);

                    WSTACK_PUSH4(s, (UWord)kptr, (UWord)vptr, ENC_MAP_PAIR, size);
                }
            } else {
                Eterm hdr;
                Uint node_sz;
                ptr = boxed_val(obj);
                hdr = *ptr;
                ASSERT(is_header(hdr));
                switch(hdr & _HEADER_MAP_SUBTAG_MASK) {
                case HAMT_SUBTAG_HEAD_ARRAY:
                    *ep++ = MAP_EXT;
                    ptr++;
                    put_int32(*ptr, ep); ep += 4;
                    node_sz = 16;
                    break;
                case HAMT_SUBTAG_HEAD_BITMAP:
                    *ep++ = MAP_EXT;
                    ptr++;
                    put_int32(*ptr, ep); ep += 4;
                    /*fall through*/
                case HAMT_SUBTAG_NODE_BITMAP:
                    node_sz = hashmap_bitcount(MAP_HEADER_VAL(hdr));
                    ASSERT(node_sz < 17);
                    break;
                default:
                    erts_exit(ERTS_ERROR_EXIT, "bad header\r\n");
                }

                ptr++;
                WSTACK_RESERVE(s, node_sz*2);
                while(node_sz--) {
                    WSTACK_FAST_PUSH(s, ENC_HASHMAP_NODE);
                    WSTACK_FAST_PUSH(s, *ptr++);
                }
            }
            break;

        case FLOAT_DEF:
            GET_DOUBLE(obj, f);
            ENSURE_BUFFER(40);
            ep += sprintf(ep, "%g", (double) f);
            break;

        case BINARY_DEF: {
            Uint bitoffs;
            Uint bitsize;
            byte* bytes;

            ERTS_GET_BINARY_BYTES(obj, bytes, bitoffs, bitsize);

            if (bitsize != 0) { goto fail; }
            /* Plain old byte-sized binary. */

            Uint len = binary_size(obj);
            ENSURE_BUFFER(len + 2);

            if (ctx && len > r * TERM_TO_JSON_MEMCPY_FACTOR) {
                WSTACK_PUSH5(s, (UWord)ep, (UWord)bytes, bitoffs,
                             ENC_BIN_COPY, 8 * len);
                ep += len + 2;
            } else {
                *ep++ = '"';
                copy_binary_to_buffer(ep, 0, bytes, bitoffs, 8 * len);
                ep += len;
                *ep++ = '"';
            }
        }
            break;

        case PID_DEF:
        case EXTERNAL_PID_DEF:
        case REF_DEF:
        case EXTERNAL_REF_DEF:
        case PORT_DEF:
        case EXTERNAL_PORT_DEF:
        case EXPORT_DEF:
        case FUN_DEF:
        default:
            goto fail;
    }

    DESTROY_WSTACK(s);
    if (ctx) {
        ASSERT(ctx->wstack.wstart == NULL);
        *reds = r;
    }
    *res = ep;
    return 0;

fail:
    DESTROY_WSTACK(s);
    if (ctx) {
        ASSERT(ctx->wstack.wstart == NULL);
        *reds = r;
    }
    return 1;
}

struct dec_json_hamt
{
    Eterm* objp; /* write result here */
    Uint size;   /* nr of leafs */
    Eterm* leaf_array;
};


/* Decode term from external format into *objp.
** On failure calls erts_factory_undo() and returns NULL
*/
static byte*
dec_json(ErtsDistExternal *edep,
         ErtsHeapFactory* factory,
         byte* ep,
         Eterm* objp,
         J2TContext* ctx)
{
#define PSTACK_TYPE struct dec_json_hamt
    PSTACK_DECLARE(hamt_array, 5);
    int n;
    ErtsAtomEncoding char_enc;
    register Eterm* hp;        /* Please don't take the address of hp */
    DECLARE_WSTACK(flat_maps); /* for preprocessing of small maps */
    Eterm* next;
    SWord reds;
#ifdef DEBUG
    Eterm* dbg_resultp = ctx ? &ctx->u.dc.res : objp;
#endif

    if (ctx) {
        reds     = ctx->reds;
        next     = ctx->u.dc.next;
        ep       = ctx->u.dc.ep;
        factory  = &ctx->u.dc.factory;

        if (ctx->state != J2TDecode) {
            int n_limit = reds;

            n = ctx->u.dc.remaining_n;
            if (ctx->state == J2TDecodeBinary) {
                n_limit *= J2T_MEMCPY_FACTOR;
                ASSERT(n_limit >= reds);
                reds -= n / J2T_MEMCPY_FACTOR;
            }
            else
                reds -= n;

            if (n > n_limit) {
                ctx->u.dc.remaining_n -= n_limit;
                n = n_limit;
                reds = 0;
            }
            else {
                ctx->u.dc.remaining_n = 0;
            }

            switch (ctx->state) {
            case J2TDecodeList:
                objp = next - 2;
                while (n > 0) {
                    objp[0] = (Eterm) next;
                    objp[1] = make_list(next);
                    next = objp;
                    objp -= 2;
                    n--;
                }
                break;

            case J2TDecodeTuple:
                objp = next - 1;
                while (n-- > 0) {
                    objp[0] = (Eterm) next;
                    next = objp;
                    objp--;
                }
                break;

            case J2TDecodeString:
                hp = factory->hp;
                hp[-1] = make_list(hp);  /* overwrite the premature NIL */
                while (n-- > 0) {
                    hp[0] = make_small(*ep++);
                    hp[1] = make_list(hp+2);
                    hp += 2;
                }
                hp[-1] = NIL;
                factory->hp = hp;
                break;

            case J2TDecodeBinary:
                sys_memcpy(ctx->u.dc.remaining_bytes, ep, n);
                ctx->u.dc.remaining_bytes += n;
                ep += n;
                break;

            default:
                ASSERT(!"Unknown state");
            }
            if (!ctx->u.dc.remaining_n) {
                ctx->state = J2TDecode;
            }
            if (reds <= 0) {
                ctx->u.dc.next = next;
                ctx->u.dc.ep = ep;
                ctx->reds = 0;
                return NULL;
            }
        }
        PSTACK_CHANGE_ALLOCATOR(hamt_array, ERTS_ALC_T_SAVED_ESTACK);
        WSTACK_CHANGE_ALLOCATOR(flat_maps, ERTS_ALC_T_SAVED_ESTACK);
        if (ctx->u.dc.hamt_array.pstart) {
            PSTACK_RESTORE(hamt_array, &ctx->u.dc.hamt_array);
        }
        if (ctx->u.dc.flat_maps.wstart) {
            WSTACK_RESTORE(flat_maps, &ctx->u.dc.flat_maps);
        }
    }
    else {
        reds = ERTS_SWORD_MAX;
        next = objp;
        *next = (Eterm) (UWord) NULL;
    }
    hp = factory->hp;

    while (next != NULL) {

        objp = next;
        next = (Eterm *) *objp;

        switch (*ep++) {
        case INTEGER_EXT:
            {
                Sint sn = get_int32(ep);

                ep += 4;
#if defined(ARCH_64)
                *objp = make_small(sn);
#else
                if (MY_IS_SSMALL(sn)) {
                    *objp = make_small(sn);
                } else {
                    *objp = small_to_big(sn, hp);
                    hp += BIG_UINT_HEAP_SIZE;
                }
#endif
                break;
            }
        case SMALL_INTEGER_EXT:
            n = get_int8(ep);
            ep++;
            *objp = make_small(n);
            break;
        case SMALL_BIG_EXT:
            n = get_int8(ep);
            ep++;
            goto big_loop;
        case LARGE_BIG_EXT:
            n = get_int32(ep);
            ep += 4;
        big_loop:
            {
                Eterm big;
                byte* first;
                byte* last;
                Uint neg;

                neg = get_int8(ep); /* Sign bit */
                ep++;

                /*
                 * Strip away leading zeroes to avoid creating illegal bignums.
                 */
                first = ep;
                last = ep + n;
                ep += n;
                do {
                    --last;
                } while (first <= last && *last == 0);

                if ((n = last - first + 1) == 0) {
                    /* Zero width bignum defaults to zero */
                    big = make_small(0);
                } else {
                    big = bytes_to_big(first, n, neg, hp);
                    if (is_nil(big))
                        goto error;
                    if (is_big(big)) {
                        hp += big_arity(big) + 1;
                    }
                }
                *objp = big;
                break;
            }
        case ATOM_CACHE_REF:
            if (edep == 0 || (edep->flags & ERTS_DIST_EXT_ATOM_TRANS_TAB) == 0) {
                goto error;
            }
            n = get_int8(ep);
            ep++;
            if (n >= edep->attab.size)
                goto error;
            ASSERT(is_atom(edep->attab.atom[n]));
            *objp = edep->attab.atom[n];
            break;
        case ATOM_EXT:
            n = get_int16(ep);
            ep += 2;
            char_enc = ERTS_ATOM_ENC_LATIN1;
            goto dec_json_atom_common;
        case SMALL_ATOM_EXT:
            n = get_int8(ep);
            ep++;
            char_enc = ERTS_ATOM_ENC_LATIN1;
            goto dec_json_atom_common;
        case ATOM_UTF8_EXT:
            n = get_int16(ep);
            ep += 2;
            char_enc = ERTS_ATOM_ENC_UTF8;
            goto dec_json_atom_common;
        case SMALL_ATOM_UTF8_EXT:
            n = get_int8(ep);
            ep++;
            char_enc = ERTS_ATOM_ENC_UTF8;
dec_json_atom_common:
            if (edep && (edep->flags & ERTS_DIST_EXT_BTT_SAFE)) {
                if (!erts_atom_get((char*)ep, n, objp, char_enc)) {
                    goto error;
                }
            } else {
                Eterm atom = erts_atom_put(ep, n, char_enc, 0);
                if (is_non_value(atom))
                    goto error;
                *objp = atom;
            }
            ep += n;
            break;
        case LARGE_TUPLE_EXT:
            n = get_int32(ep);
            ep += 4;
            goto tuple_loop;
        case SMALL_TUPLE_EXT:
            n = get_int8(ep);
            ep++;
        tuple_loop:
            *objp = make_tuple(hp);
            *hp++ = make_arityval(n);
            hp += n;
            objp = hp - 1;
            if (ctx) {
                if (reds < n) {
                    ASSERT(reds > 0);
                    ctx->state = J2TDecodeTuple;
                    ctx->u.dc.remaining_n = n - reds;
                    n = reds;
                }
                reds -= n;
            }
            while (n-- > 0) {
                objp[0] = (Eterm) next;
                next = objp;
                objp--;
            }
            break;
        case NIL_EXT:
            *objp = NIL;
            break;
        case LIST_EXT:
            n = get_int32(ep);
            ep += 4;
            if (n == 0) {
                next = objp;
                break;
            }
            *objp = make_list(hp);
            hp += 2 * n;
            objp = hp - 2;
            objp[0] = (Eterm) (objp+1);
            objp[1] = (Eterm) next;
            next = objp;
            objp -= 2;
            n--;
            if (ctx) {
                if (reds < n) {
                    ctx->state = J2TDecodeList;
                    ctx->u.dc.remaining_n = n - reds;
                    n = reds;
                }
                reds -= n;
            }
            while (n > 0) {
                objp[0] = (Eterm) next;
                objp[1] = make_list(next);
                next = objp;
                objp -= 2;
                n--;
            }
            break;
        case STRING_EXT:
            n = get_int16(ep);
            ep += 2;
            if (n == 0) {
                *objp = NIL;
                break;
            }
            *objp = make_list(hp);
            if (ctx) {
                if (reds < n) {
                    ctx->state = J2TDecodeString;
                    ctx->u.dc.remaining_n = n - reds;
                    n = reds;
                }
                reds -= n;
            }
            while (n-- > 0) {
                hp[0] = make_small(*ep++);
                hp[1] = make_list(hp+2);
                hp += 2;
            }
            hp[-1] = NIL;
            break;
        case FLOAT_EXT:
            {
                FloatDef ff;

                if (sys_chars_to_double((char*)ep, &ff.fd) != 0) {
                    goto error;
                }
                ep += 31;
                *objp = make_float(hp);
                PUT_DOUBLE(ff, hp);
                hp += FLOAT_SIZE_OBJECT;
                break;
            }
        case NEW_FLOAT_EXT:
            {
                FloatDef ff;
#ifndef NO_FPE_SIGNALS
                volatile unsigned long *fpexnp = erts_get_current_fp_exception();
#endif

#if defined(WORDS_BIGENDIAN) || defined(DOUBLE_MIDDLE_ENDIAN)
                ff.fw[0] = get_int32(ep);
                ep += 4;
                ff.fw[1] = get_int32(ep);
                ep += 4;
#else
                ff.fw[1] = get_int32(ep);
                ep += 4;
                ff.fw[0] = get_int32(ep);
                ep += 4;
#endif
                __ERTS_FP_CHECK_INIT(fpexnp);
                __ERTS_FP_ERROR_THOROUGH(fpexnp, ff.fd, goto error);
                *objp = make_float(hp);
                PUT_DOUBLE(ff, hp);
                hp += FLOAT_SIZE_OBJECT;
                break;
            }
        case PID_EXT:
        case NEW_PID_EXT:
            factory->hp = hp;
            ep = dec_pid(edep, factory, ep, objp, ep[-1]);
            hp = factory->hp;
            if (ep == NULL) {
                goto error;
            }
            break;
        case PORT_EXT:
        case NEW_PORT_EXT:
            {
                Eterm sysname;
                ErlNode *node;
                Uint num;
                Uint32 cre;
                byte tag = ep[-1];

                if ((ep = dec_atom(edep, ep, &sysname)) == NULL) {
                    goto error;
                }
                if ((num = get_int32(ep)) > ERTS_MAX_PORT_NUMBER) {
                    goto error;
                }
                ep += 4;
                if (tag == PORT_EXT) {
                    cre = get_int8(ep);
                    ep++;
                    if (!is_valid_creation(cre)) {
                        goto error;
                    }
                }
                else {
                    cre = get_int32(ep);
                    ep += 4;
                }
                node = dec_get_node(sysname, cre);
                if(node == erts_this_node) {
                    *objp = make_internal_port(num);
                }
                else {
                    ExternalThing *etp = (ExternalThing *) hp;
                    hp += EXTERNAL_THING_HEAD_SIZE + 1;

                    etp->header = make_external_port_header(1);
                    etp->next = factory->off_heap->first;
                    etp->node = node;
                    etp->data.ui[0] = num;

                    factory->off_heap->first = (struct erl_off_heap_header*)etp;
                    *objp = make_external_port(etp);
                }

                break;
            }
        case REFERENCE_EXT:
            {
                Eterm sysname;
                ErlNode *node;
                int i;
                Uint32 cre;
                Uint32 *ref_num;
                Uint32 r0;
                Uint ref_words;

                ref_words = 1;

                if ((ep = dec_atom(edep, ep, &sysname)) == NULL)
                    goto error;
                if ((r0 = get_int32(ep)) >= MAX_REFERENCE )
                    goto error;
                ep += 4;

                cre = get_int8(ep);
                ep += 1;
                if (!is_valid_creation(cre)) {
                    goto error;
                }
                goto ref_ext_common;

            case NEW_REFERENCE_EXT:
                ref_words = get_int16(ep);
                ep += 2;

                if ((ep = dec_atom(edep, ep, &sysname)) == NULL)
                    goto error;

                cre = get_int8(ep);
                ep += 1;
                if (!is_valid_creation(cre)) {
                    goto error;
                }
                r0 = get_int32(ep);
                ep += 4;
                if (r0 >= MAX_REFERENCE)
                    goto error;
                goto ref_ext_common;

            case NEWER_REFERENCE_EXT:
                ref_words = get_int16(ep);
                ep += 2;

                if ((ep = dec_atom(edep, ep, &sysname)) == NULL)
                    goto error;

                cre = get_int32(ep);
                ep += 4;
                r0 = get_int32(ep); /* allow full word */
                ep += 4;

            ref_ext_common: {
                ErtsORefThing *rtp;

                if (ref_words > ERTS_MAX_REF_NUMBERS)
                    goto error;

                node = dec_get_node(sysname, cre);
                if(node == erts_this_node) {

                    rtp = (ErtsORefThing *) hp;
                    ref_num = &rtp->num[0];
                    if (ref_words != ERTS_REF_NUMBERS) {
                        int i;
                        if (ref_words > ERTS_REF_NUMBERS)
                            goto error; /* Not a ref that we created... */
                        for (i = ref_words; i < ERTS_REF_NUMBERS; i++)
                            ref_num[i] = 0;
                    }

#ifdef ERTS_ORDINARY_REF_MARKER
                    rtp->marker = ERTS_ORDINARY_REF_MARKER;
#endif
                    hp += ERTS_REF_THING_SIZE;
                    rtp->header = ERTS_REF_THING_HEADER;
                    *objp = make_internal_ref(rtp);
                }
                else {
                    ExternalThing *etp = (ExternalThing *) hp;
                    rtp = NULL;
#if defined(ARCH_64)
                    hp += EXTERNAL_THING_HEAD_SIZE + ref_words/2 + 1;
#else
                    hp += EXTERNAL_THING_HEAD_SIZE + ref_words;
#endif

#if defined(ARCH_64)
                    etp->header = make_external_ref_header(ref_words/2 + 1);
#else
                    etp->header = make_external_ref_header(ref_words);
#endif
                    etp->next = factory->off_heap->first;
                    etp->node = node;

                    factory->off_heap->first = (struct erl_off_heap_header*)etp;
                    *objp = make_external_ref(etp);
                    ref_num = &(etp->data.ui32[0]);
#if defined(ARCH_64)
                    *(ref_num++) = ref_words /* 32-bit arity */;
#endif
                }

                ref_num[0] = r0;

                for(i = 1; i < ref_words; i++) {
                    ref_num[i] = get_int32(ep);
                    ep += 4;
                }
#if defined(ARCH_64)
                if ((1 + ref_words) % 2)
                    ref_num[ref_words] = 0;
#endif
                if (node == erts_this_node) {
                    /* Check if it was a magic reference... */
                    ErtsMagicBinary *mb = erts_magic_ref_lookup_bin(ref_num);
                    if (mb) {
                        /*
                         * Was a magic ref; adjust it...
                         *
                         * Refc on binary was increased by lookup above...
                         */
                        ASSERT(rtp);
                        hp = (Eterm *) rtp;
                        write_magic_ref_thing(hp, factory->off_heap, mb);
                        OH_OVERHEAD(factory->off_heap,
                                    mb->orig_size / sizeof(Eterm));
                        hp += ERTS_MAGIC_REF_THING_SIZE;
                    }
                }
                break;
            }
            }
        case BINARY_EXT:
            {
                n = get_int32(ep);
                ep += 4;

                if ((unsigned)n <= ERL_ONHEAP_BIN_LIMIT) {
                    ErlHeapBin* hb = (ErlHeapBin *) hp;

                    hb->thing_word = header_heap_bin(n);
                    hb->size = n;
                    hp += heap_bin_size(n);
                    sys_memcpy(hb->data, ep, n);
                    *objp = make_binary(hb);
                } else {
                    Binary* dbin = erts_bin_nrml_alloc(n);
                    ProcBin* pb;
                    pb = (ProcBin *) hp;
                    hp += PROC_BIN_SIZE;
                    pb->thing_word = HEADER_PROC_BIN;
                    pb->size = n;
                    pb->next = factory->off_heap->first;
                    factory->off_heap->first = (struct erl_off_heap_header*)pb;
                    OH_OVERHEAD(factory->off_heap, pb->size / sizeof(Eterm));
                    pb->val = dbin;
                    pb->bytes = (byte*) dbin->orig_bytes;
                    pb->flags = 0;
                    *objp = make_binary(pb);
                    if (ctx) {
                        int n_limit = reds * J2T_MEMCPY_FACTOR;
                        if (n > n_limit) {
                            ctx->state = J2TDecodeBinary;
                            ctx->u.dc.remaining_n = n - n_limit;
                            ctx->u.dc.remaining_bytes = dbin->orig_bytes + n_limit;
                            n = n_limit;
                            reds = 0;
                        }
                        else
                            reds -= n / J2T_MEMCPY_FACTOR;
                    }
                    sys_memcpy(dbin->orig_bytes, ep, n);
                }
                ep += n;
                break;
            }
        case BIT_BINARY_EXT:
            {
                Eterm bin;
                ErlSubBin* sb;
                Uint bitsize;

                n = get_int32(ep);
                bitsize = ep[4];
                if (((bitsize==0) != (n==0)) || bitsize > 8)
                    goto error;
                ep += 5;
                if ((unsigned)n <= ERL_ONHEAP_BIN_LIMIT) {
                    ErlHeapBin* hb = (ErlHeapBin *) hp;

                    hb->thing_word = header_heap_bin(n);
                    hb->size = n;
                    sys_memcpy(hb->data, ep, n);
                    bin = make_binary(hb);
                    hp += heap_bin_size(n);
                    ep += n;
                } else {
                    Binary* dbin = erts_bin_nrml_alloc(n);
                    ProcBin* pb;

                    pb = (ProcBin *) hp;
                    pb->thing_word = HEADER_PROC_BIN;
                    pb->size = n;
                    pb->next = factory->off_heap->first;
                    factory->off_heap->first = (struct erl_off_heap_header*)pb;
                    OH_OVERHEAD(factory->off_heap, pb->size / sizeof(Eterm));
                    pb->val = dbin;
                    pb->bytes = (byte*) dbin->orig_bytes;
                    pb->flags = 0;
                    bin = make_binary(pb);
                    hp += PROC_BIN_SIZE;
                    if (ctx) {
                        int n_limit = reds * J2T_MEMCPY_FACTOR;
                        if (n > n_limit) {
                            ctx->state = J2TDecodeBinary;
                            ctx->u.dc.remaining_n = n - n_limit;
                            ctx->u.dc.remaining_bytes = dbin->orig_bytes + n_limit;
                            n = n_limit;
                            reds = 0;
                        }
                        else
                            reds -= n / J2T_MEMCPY_FACTOR;
                    }
                    sys_memcpy(dbin->orig_bytes, ep, n);
                    ep += n;
                    n = pb->size;
                }

                if (bitsize == 8 || n == 0) {
                    *objp = bin;
                } else {
                    sb = (ErlSubBin *)hp;
                    sb->thing_word = HEADER_SUB_BIN;
                    sb->orig = bin;
                    sb->size = n - 1;
                    sb->bitsize = bitsize;
                    sb->bitoffs = 0;
                    sb->offs = 0;
                    sb->is_writable = 0;
                    *objp = make_binary(sb);
                    hp += ERL_SUB_BIN_SIZE;
                }
                break;
            }
        case EXPORT_EXT:
            {
                Eterm mod;
                Eterm name;
                Eterm temp;
                Sint arity;

                if ((ep = dec_atom(edep, ep, &mod)) == NULL) {
                    goto error;
                }
                if ((ep = dec_atom(edep, ep, &name)) == NULL) {
                    goto error;
                }
                factory->hp = hp;
                ep = dec_json(edep, factory, ep, &temp, NULL);
                hp = factory->hp;
                if (ep == NULL) {
                    goto error;
                }
                if (!is_small(temp)) {
                    goto error;
                }
                arity = signed_val(temp);
                if (arity < 0) {
                    goto error;
                }
                if (edep && (edep->flags & ERTS_DIST_EXT_BTT_SAFE)) {
                    if (!erts_active_export_entry(mod, name, arity))
                        goto error;
                }
                *objp = make_export(hp);
                *hp++ = HEADER_EXPORT;
                *hp++ = (Eterm) erts_export_get_or_make_stub(mod, name, arity);
                break;
            }
            break;
        case MAP_EXT:
            {
                Uint32 size,n;
                Eterm *kptr,*vptr;
                Eterm keys;

                size = get_int32(ep); ep += 4;

                if (size <= MAP_SMALL_MAP_LIMIT) {
                    flatmap_t *mp;

                    keys  = make_tuple(hp);
                    *hp++ = make_arityval(size);
                    hp   += size;
                    kptr = hp - 1;

                    mp    = (flatmap_t*)hp;
                    hp   += MAP_HEADER_FLATMAP_SZ;
                    hp   += size;
                    vptr = hp - 1;

                    /* kptr, last word for keys
                     * vptr, last word for values
                     */

                    WSTACK_PUSH(flat_maps, (UWord)mp);
                    mp->thing_word = MAP_HEADER_FLATMAP;
                    mp->size       = size;
                    mp->keys       = keys;
                    *objp          = make_flatmap(mp);

                    for (n = size; n; n--) {
                        *vptr = (Eterm) next;
                        *kptr = (Eterm) vptr;
                        next  = kptr;
                        vptr--;
                        kptr--;
                    }
                }
                else {  /* Make hamt */
                    struct dec_json_hamt* hamt = PSTACK_PUSH(hamt_array);

                    hamt->objp = objp;
                    hamt->size = size;
                    hamt->leaf_array = hp;

                    for (n = size; n; n--) {
                        CDR(hp) = (Eterm) next;
                        CAR(hp) = (Eterm) &CDR(hp);
                        next = &CAR(hp);
                        hp += 2;
                    }
                }
            }
            break;
        case NEW_FUN_EXT:
            {
                ErlFunThing* funp = (ErlFunThing *) hp;
                Uint arity;
                Eterm module;
                byte* uniq;
                int index;
                Sint old_uniq;
                Sint old_index;
                unsigned num_free;
                int i;
                Eterm temp;

                ep += 4;	/* Skip total size in bytes */
                arity = *ep++;
                uniq = ep;
                ep += 16;
                index = get_int32(ep);
                ep += 4;
                num_free = get_int32(ep);
                ep += 4;
                hp += ERL_FUN_SIZE;
                hp += num_free;
                funp->thing_word = HEADER_FUN;
                funp->num_free = num_free;
                *objp = make_fun(funp);

                /* Module */
                if ((ep = dec_atom(edep, ep, &module)) == NULL) {
                    goto error;
                }
                factory->hp = hp;
                /* Index */
                if ((ep = dec_json(edep, factory, ep, &temp, NULL)) == NULL) {
                    goto error;
                }
                if (!is_small(temp)) {
                    goto error;
                }
                old_index = unsigned_val(temp);

                /* Uniq */
                if ((ep = dec_json(edep, factory, ep, &temp, NULL)) == NULL) {
                    goto error;
                }
                if (!is_small(temp)) {
                    goto error;
                }
                old_uniq = unsigned_val(temp);

                /*
                 * It is safe to link the fun into the fun list only when
                 * no more validity tests can fail.
                 */
                funp->next = factory->off_heap->first;
                factory->off_heap->first = (struct erl_off_heap_header*)funp;

                funp->fe = erts_put_fun_entry2(module, old_uniq, old_index,
                                               uniq, index, arity);
                funp->arity = arity;
#ifdef HIPE
                if (funp->fe->native_address == NULL) {
                    hipe_set_closure_stub(funp->fe);
                }
#endif
                hp = factory->hp;

                /* Environment */
                for (i = num_free-1; i >= 0; i--) {
                    funp->env[i] = (Eterm) next;
                    next = funp->env + i;
                }
                /* Creator */
                funp->creator = (Eterm) next;
                next = &(funp->creator);
                break;
            }
        case FUN_EXT:
            {
                ErlFunThing* funp = (ErlFunThing *) hp;
                Eterm module;
                Sint old_uniq;
                Sint old_index;
                unsigned num_free;
                int i;
                Eterm temp;

                num_free = get_int32(ep);
                ep += 4;
                hp += ERL_FUN_SIZE;
                hp += num_free;
                factory->hp = hp;
                funp->thing_word = HEADER_FUN;
                funp->num_free = num_free;
                *objp = make_fun(funp);

                /* Creator pid */
                if ((*ep != PID_EXT && *ep != NEW_PID_EXT)
                    || (ep = dec_pid(edep, factory, ep+1,
                                     &funp->creator, *ep))==NULL) {
                    goto error;
                }

                /* Module */
                if ((ep = dec_atom(edep, ep, &module)) == NULL) {
                    goto error;
                }

                /* Index */
                if ((ep = dec_json(edep, factory, ep, &temp, NULL)) == NULL) {
                    goto error;
                }
                if (!is_small(temp)) {
                    goto error;
                }
                old_index = unsigned_val(temp);

                /* Uniq */
                if ((ep = dec_json(edep, factory, ep, &temp, NULL)) == NULL) {
                    goto error;
                }
                if (!is_small(temp)) {
                    goto error;
                }

                /*
                 * It is safe to link the fun into the fun list only when
                 * no more validity tests can fail.
                 */
                funp->next = factory->off_heap->first;
                factory->off_heap->first = (struct erl_off_heap_header*)funp;
                old_uniq = unsigned_val(temp);

                funp->fe = erts_put_fun_entry(module, old_uniq, old_index);
                funp->arity = funp->fe->address[-1] - num_free;
                hp = factory->hp;

                /* Environment */
                for (i = num_free-1; i >= 0; i--) {
                    funp->env[i] = (Eterm) next;
                    next = funp->env + i;
                }
                break;
            }
        case ATOM_INTERNAL_REF2:
            n = get_int16(ep);
            ep += 2;
            if (n >= atom_table_size()) {
                goto error;
            }
            *objp = make_atom(n);
            break;
        case ATOM_INTERNAL_REF3:
            n = get_int24(ep);
            ep += 3;
            if (n >= atom_table_size()) {
                goto error;
            }
            *objp = make_atom(n);
            break;

        case BINARY_INTERNAL_REF:
            {
                ProcBin* pb = (ProcBin*) hp;
                sys_memcpy(pb, ep, sizeof(ProcBin));
                ep += sizeof(ProcBin);

                erts_refc_inc(&pb->val->intern.refc, 1);
                hp += PROC_BIN_SIZE;
                pb->next = factory->off_heap->first;
                factory->off_heap->first = (struct erl_off_heap_header*)pb;
                OH_OVERHEAD(factory->off_heap, pb->size / sizeof(Eterm));
                pb->flags = 0;
                *objp = make_binary(pb);
                break;
            }
        case BIT_BINARY_INTERNAL_REF:
            {
                Sint bitoffs = *ep++;
                Sint bitsize = *ep++;
                ProcBin* pb = (ProcBin*) hp;
                ErlSubBin* sub;
                sys_memcpy(pb, ep, sizeof(ProcBin));
                ep += sizeof(ProcBin);

                erts_refc_inc(&pb->val->intern.refc, 1);
                hp += PROC_BIN_SIZE;
                pb->next = factory->off_heap->first;
                factory->off_heap->first = (struct erl_off_heap_header*)pb;
                OH_OVERHEAD(factory->off_heap, pb->size / sizeof(Eterm));
                pb->flags = 0;

                sub = (ErlSubBin*)hp;
                sub->thing_word = HEADER_SUB_BIN;
                sub->size = pb->size - (bitoffs + bitsize + 7)/8;
                sub->offs = 0;
                sub->bitoffs = bitoffs;
                sub->bitsize = bitsize;
                sub->is_writable = 0;
                sub->orig = make_binary(pb);

                hp += ERL_SUB_BIN_SIZE;
                *objp = make_binary(sub);
                break;
            }

        default:
            goto error;
        }

        if (--reds <= 0) {
            if (ctx) {
                if (next || ctx->state != J2TDecode) {
                    ctx->u.dc.ep = ep;
                    ctx->u.dc.next = next;
                    ctx->u.dc.factory.hp = hp;
                    if (!WSTACK_ISEMPTY(flat_maps)) {
                        WSTACK_SAVE(flat_maps, &ctx->u.dc.flat_maps);
                    }
                    if (!PSTACK_IS_EMPTY(hamt_array)) {
                        PSTACK_SAVE(hamt_array, &ctx->u.dc.hamt_array);
                    }
                    ctx->reds = 0;
                    return NULL;
                }
            }
            else {
                reds = ERTS_SWORD_MAX;
            }
        }
    }

    ASSERT(hp <= factory->hp_end
           || (factory->mode == FACTORY_CLOSED && is_immed(*dbg_resultp)));
    factory->hp = hp;
    /*
     * From here on factory may produce (more) heap fragments
     */

    if (!PSTACK_IS_EMPTY(hamt_array)) {
        do {
            struct dec_json_hamt* hamt = PSTACK_TOP(hamt_array);

            *hamt->objp = erts_hashmap_from_array(factory,
                                                  hamt->leaf_array,
                                                  hamt->size,
                                                  1);
            if (is_non_value(*hamt->objp))
                goto error_hamt;

            (void) PSTACK_POP(hamt_array);
        } while (!PSTACK_IS_EMPTY(hamt_array));
        PSTACK_DESTROY(hamt_array);
    }

    /* Iterate through all the (flat)maps and check for validity and sort keys
     * - done here for when we know it is complete.
     */

    while(!WSTACK_ISEMPTY(flat_maps)) {
        next = (Eterm *)WSTACK_POP(flat_maps);
        if (!erts_validate_and_sort_flatmap((flatmap_t*)next))
            goto error;
    }
    WSTACK_DESTROY(flat_maps);

    ASSERT((Eterm*)*dbg_resultp != NULL);

    if (ctx) {
        ctx->state = J2TDone;
        ctx->reds = reds;
    }

    return ep;

error:
    /* UNDO:
     * Must unlink all off-heap objects that may have been
     * linked into the process.
     */
    if (factory->mode != FACTORY_CLOSED) {
        if (factory->hp < hp) { /* Sometimes we used hp and sometimes factory->hp */
            factory->hp = hp;   /* the largest must be the freshest */
        }
    }
    else ASSERT(!factory->hp || factory->hp == hp);

error_hamt:
    erts_factory_undo(factory);
    PSTACK_DESTROY(hamt_array);
    if (ctx) {
        ctx->state = J2TDecodeFail;
        ctx->reds = reds;
    }
    WSTACK_DESTROY(flat_maps);

    return NULL;
}


static Sint
decoded_size(byte *ep, byte* endp, int internal_tags, J2TContext* ctx)
{
    int heap_size;
    int terms;
    int atom_extra_skip;
    Uint n;
    SWord reds;

    if (ctx) {
        reds = ctx->reds;
        if (ctx->u.sc.ep) {
            heap_size = ctx->u.sc.heap_size;
            terms = ctx->u.sc.terms;
            ep = ctx->u.sc.ep;
            atom_extra_skip = ctx->u.sc.atom_extra_skip;
            goto init_done;
        }
    }
    else
        reds = 0; /* not used but compiler warns anyway */

    heap_size = 0;
    terms = 1;
    atom_extra_skip = 0;
init_done:

#define SKIP(sz)				\
    do {					\
        if ((sz) <= endp-ep) {			\
            ep += (sz);				\
        } else { goto error; };			\
    } while (0)

#define SKIP2(sz1, sz2)				\
    do {					\
        Uint sz = (sz1) + (sz2);		\
        if (sz1 < sz && (sz) <= endp-ep) {	\
            ep += (sz);				\
        } else { goto error; }			\
    } while (0)

#define CHKSIZE(sz)				\
    do {					\
         if ((sz) > endp-ep) { goto error; }	\
    } while (0)

#define ADDTERMS(n)				\
    do {					\
        int before = terms;		        \
        terms += (n);                           \
        if (terms < before) goto error;     	\
    } while (0)

    ASSERT(terms > 0);
    do {
        int tag;
        CHKSIZE(1);
        tag = ep++[0];
        switch (tag) {
        case INTEGER_EXT:
            SKIP(4);
#if !defined(ARCH_64)
            heap_size += BIG_UINT_HEAP_SIZE;
#endif
            break;
        case SMALL_INTEGER_EXT:
            SKIP(1);
            break;
        case SMALL_BIG_EXT:
            CHKSIZE(1);
            n = ep[0];		/* number of bytes */
            SKIP2(n, 1+1);		/* skip size,sign,digits */
            heap_size += 1+(n+sizeof(Eterm)-1)/sizeof(Eterm); /* XXX: 1 too much? */
            break;
        case LARGE_BIG_EXT:
            CHKSIZE(4);
            n = get_int32(ep);
            if (n > BIG_ARITY_MAX*sizeof(ErtsDigit)) {
                goto error;
            }
            SKIP2(n,4+1);		/* skip, size,sign,digits */
            heap_size += 1+1+(n+sizeof(Eterm)-1)/sizeof(Eterm); /* XXX: 1 too much? */
            break;
        case ATOM_EXT:
            CHKSIZE(2);
            n = get_int16(ep);
            if (n > MAX_ATOM_CHARACTERS) {
                goto error;
            }
            SKIP(n+2+atom_extra_skip);
            atom_extra_skip = 0;
            break;
        case ATOM_UTF8_EXT:
            CHKSIZE(2);
            n = get_int16(ep);
            ep += 2;
            if (n > MAX_ATOM_SZ_LIMIT) {
                goto error;
            }
            SKIP(n+atom_extra_skip);
            atom_extra_skip = 0;
            break;
        case SMALL_ATOM_EXT:
            CHKSIZE(1);
            n = get_int8(ep);
            if (n > MAX_ATOM_CHARACTERS) {
                goto error;
            }
            SKIP(n+1+atom_extra_skip);
            atom_extra_skip = 0;
            break;
        case SMALL_ATOM_UTF8_EXT:
            CHKSIZE(1);
            n = get_int8(ep);
            ep++;
            if (n > MAX_ATOM_SZ_LIMIT) {
                goto error;
            }
            SKIP(n+atom_extra_skip);
            atom_extra_skip = 0;
            break;
        case ATOM_CACHE_REF:
            SKIP(1+atom_extra_skip);
            atom_extra_skip = 0;
            break;
        case NEW_PID_EXT:
            atom_extra_skip = 12;
            goto case_PID;
        case PID_EXT:
            atom_extra_skip = 9;
        case_PID:
            /* In case it is an external pid */
            heap_size += EXTERNAL_THING_HEAD_SIZE + 1;
            terms++;
            break;
        case NEW_PORT_EXT:
            atom_extra_skip = 8;
            goto case_PORT;
        case PORT_EXT:
            atom_extra_skip = 5;
        case_PORT:
            /* In case it is an external port */
            heap_size += EXTERNAL_THING_HEAD_SIZE + 1;
            terms++;
            break;
        case NEWER_REFERENCE_EXT:
            atom_extra_skip = 4;
            goto case_NEW_REFERENCE;
        case NEW_REFERENCE_EXT:
            atom_extra_skip = 1;
        case_NEW_REFERENCE:
            {
                int id_words;

                CHKSIZE(2);
                id_words = get_int16(ep);

                if (id_words > ERTS_MAX_REF_NUMBERS)
                    goto error;

                ep += 2;
                atom_extra_skip += 4*id_words;
                /* In case it is an external ref */
#if defined(ARCH_64)
                heap_size += EXTERNAL_THING_HEAD_SIZE + id_words/2 + 1;
#else
                heap_size += EXTERNAL_THING_HEAD_SIZE + id_words;
#endif
                terms++;
                break;
            }
        case REFERENCE_EXT:
            /* In case it is an external ref */
            heap_size += EXTERNAL_THING_HEAD_SIZE + 1;
            atom_extra_skip = 5;
            terms++;
            break;
        case NIL_EXT:
            break;
        case LIST_EXT:
            CHKSIZE(4);
            n = get_int32(ep);
            ep += 4;
            ADDTERMS(n);
            terms++;
            heap_size += 2 * n;
            break;
        case SMALL_TUPLE_EXT:
            CHKSIZE(1);
            n = *ep++;
            terms += n;
            heap_size += n + 1;
            break;
        case LARGE_TUPLE_EXT:
            CHKSIZE(4);
            n = get_int32(ep);
            ep += 4;
            ADDTERMS(n);
            heap_size += n + 1;
            break;
        case MAP_EXT:
            CHKSIZE(4);
            n = get_int32(ep);
            ep += 4;
            ADDTERMS(2*n);
            if (n <= MAP_SMALL_MAP_LIMIT) {
                heap_size += 3 + n + 1 + n;
            } else {
                heap_size += HASHMAP_ESTIMATED_HEAP_SIZE(n);
            }
            break;
        case STRING_EXT:
            CHKSIZE(2);
            n = get_int16(ep);
            SKIP(n+2);
            heap_size += 2 * n;
            break;
        case FLOAT_EXT:
            SKIP(31);
            heap_size += FLOAT_SIZE_OBJECT;
            break;
        case NEW_FLOAT_EXT:
            SKIP(8);
            heap_size += FLOAT_SIZE_OBJECT;
            break;
        case BINARY_EXT:
            CHKSIZE(4);
            n = get_int32(ep);
            SKIP2(n, 4);
            if (n <= ERL_ONHEAP_BIN_LIMIT) {
                heap_size += heap_bin_size(n);
            } else {
                heap_size += PROC_BIN_SIZE;
            }
            break;
        case BIT_BINARY_EXT:
            {
                CHKSIZE(5);
                n = get_int32(ep);
                SKIP2(n, 5);
                if (n <= ERL_ONHEAP_BIN_LIMIT) {
                    heap_size += heap_bin_size(n) + ERL_SUB_BIN_SIZE;
                } else {
                    heap_size += PROC_BIN_SIZE + ERL_SUB_BIN_SIZE;
                }
            }
            break;
        case EXPORT_EXT:
            terms += 3;
            heap_size += 2;
            break;
        case NEW_FUN_EXT:
            {
                unsigned num_free;
                Uint total_size;

                CHKSIZE(1+16+4+4);
                total_size = get_int32(ep);
                CHKSIZE(total_size);
                ep += 1+16+4+4;
                /*FALLTHROUGH*/

            case FUN_EXT:
                CHKSIZE(4);
                num_free = get_int32(ep);
                ep += 4;
                if (num_free > MAX_ARG) {
                    goto error;
                }
                terms += 4 + num_free;
                heap_size += ERL_FUN_SIZE + num_free;
                break;
            }
        case ATOM_INTERNAL_REF2:
            SKIP(2+atom_extra_skip);
            atom_extra_skip = 0;
            break;
        case ATOM_INTERNAL_REF3:
            SKIP(3+atom_extra_skip);
            atom_extra_skip = 0;
            break;

        case BINARY_INTERNAL_REF:
            if (!internal_tags) {
                goto error;
            }
            SKIP(sizeof(ProcBin));
            heap_size += PROC_BIN_SIZE;
            break;
        case BIT_BINARY_INTERNAL_REF:
            if (!internal_tags) {
                goto error;
            }
            SKIP(2+sizeof(ProcBin));
            heap_size += PROC_BIN_SIZE + ERL_SUB_BIN_SIZE;
            break;
        default:
            goto error;
        }
        terms--;

        if (ctx && --reds <= 0 && terms > 0) {
            ctx->u.sc.heap_size = heap_size;
            ctx->u.sc.terms = terms;
            ctx->u.sc.ep = ep;
            ctx->u.sc.atom_extra_skip = atom_extra_skip;
            ctx->reds = 0;
            return 0;
        }
    }while (terms > 0);

    /* 'terms' may be non-zero if it has wrapped around */
    if (terms == 0) {
        if (ctx) {
            ctx->state = J2TDecodeInit;
            ctx->reds = reds;
        }
        return heap_size;
    }

error:
    if (ctx) {
        ctx->state = J2TBadArg;
    }
    return -1;
#undef SKIP
#undef SKIP2
#undef CHKSIZE
}
