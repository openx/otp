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

#include "sys.h"
#include "erl_vm.h"
#include "global.h"
#include "erl_process.h"
#include "error.h"
#include "atom.h"
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

// static byte* enc_json(Eterm, byte*, Uint32 flags);
static int enc_json_int(TTBEncodeContext* ctx, Eterm obj, byte* ep, Uint32 dflags, Sint *reds_arg, Binary **result_bin_arg);

static BIF_RETTYPE term_to_json_trap_1(BIF_ALIST_1);

static Eterm erts_term_to_json_int(Process* p, Eterm Term, Uint flags, Binary *context_b);


void erts_init_json(void) {
    erts_init_trap_export(&term_to_json_trap_export,
                          am_erts_internal, am_term_to_json_trap, 1,
                          &term_to_json_trap_1);
}

/**********************************************************************/

/* This function will be called to continue work when term_to_json_1 returns
   via BIF_TRAP1 (or a related macro such as ERTS_BIF_PREP_TRAP1). */
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
    Eterm res = erts_term_to_json_int(BIF_P, BIF_ARG_1, /* TERM_TO_JSON_DFLAGS */ 0, NULL);
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
    Uint flags = 0; // TERM_TO_JSON_DFLAGS;
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

#if 0
static Eterm
erts_term_to_json_simple(Process* p, Eterm Term, Uint size, Uint flags)
{
    Eterm bin;
    size_t real_size;
    byte* endp;
    byte* bytes;

    bin = new_binary(p, (byte *)NULL, size);
    bytes = binary_bytes(bin);
    endp = enc_json(Term, bytes, flags);
    if (endp == NULL) {
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
#endif

/* Define EXTREME_TTB_TRAPPING for testing in dist.h */

#define TERM_TO_JSON_INITIAL_SIZE 1024
#define TERM_TO_JSON_LOOP_FACTOR TERM_TO_BINARY_LOOP_FACTOR
#define TERM_TO_JSON_MEMCPY_FACTOR 8

static int ttj_context_destructor(Binary *context_bin)
{
    TTBContext *context = ERTS_MAGIC_BIN_DATA(context_bin);
    if (context->alive) {
        context->alive = 0;
        ASSERT(context->state == TTBEncode);
        DESTROY_SAVED_WSTACK(&context->s.ec.wstack);
        if (context->s.ec.result_bin != NULL) { /* Set to NULL if ever made alive! */
            ASSERT(erts_refc_read(&(context->s.ec.result_bin->intern.refc), 1));
            erts_bin_free(context->s.ec.result_bin);
            context->s.ec.result_bin = NULL;
        }
    }
    return 1;
}

static Eterm erts_term_to_json_int(Process* p, Eterm Term, Uint flags, Binary *context_b)
{
#ifndef EXTREME_TTB_TRAPPING
    Sint reds = (Sint) (ERTS_BIF_REDS_LEFT(p) * TERM_TO_JSON_LOOP_FACTOR);
#else
    Sint reds = 20; /* For testing */
#endif
    Sint initial_reds = reds;
    TTBContext context_buf;
    TTBContext *context;
    byte *bytes;

    if (context_b == NULL) {
        // First call; initialize context.
        context_buf.alive = 1;
        context_buf.state = TTBEncode;
        context_buf.s.ec.flags = flags;
        context_buf.s.ec.level = 0; // unused
        context_buf.s.ec.ep = NULL;
        context_buf.s.ec.obj = NIL; // Would be nice if there was in invalid tag.
        context_buf.s.ec.wstack.wstart = NULL;
        context_buf.s.ec.result_bin = erts_bin_nrml_alloc(TERM_TO_JSON_INITIAL_SIZE);
        context = &context_buf;
    } else {
        context = ERTS_MAGIC_BIN_DATA(context_b);
    }

    bytes = (byte *) context->s.ec.result_bin->orig_bytes;

    flags = context->s.ec.flags;
    if (enc_json_int(&context->s.ec, Term, bytes, flags, &reds, &context->s.ec.result_bin) < 0) {
        // Ran out of reductions; yield.
        Eterm *hp;
        Eterm c_term;
        Eterm res;

        if (context_b == NULL) {
            context_b = erts_create_magic_binary(sizeof (TTBContext), ttj_context_destructor);
            context = ERTS_MAGIC_BIN_DATA(context_b);
            memcpy(context, &context_buf, sizeof (TTBContext));
        }

        hp = HAlloc(p, ERTS_MAGIC_REF_THING_SIZE+3);
        c_term = erts_mk_magic_ref(&hp, &MSO(p), context_b);
        res = TUPLE2(hp, Term, c_term);
        BUMP_ALL_REDS(p);
        return res; // return `{Term, Context}'.
    } else {
        // Finished; create return value.
        Binary *result_bin = context->s.ec.result_bin;
        size_t real_size = result_bin->orig_size;
        ProcBin* pb;

        BUMP_REDS(p, (initial_reds - reds) / TERM_TO_JSON_LOOP_FACTOR);
        context->s.ec.result_bin = NULL;
        context->alive = 0;
        pb = (ProcBin *) HAlloc(p, PROC_BIN_SIZE);
        pb->thing_word = HEADER_PROC_BIN;
        pb->size = real_size;
        pb->next = MSO(p).first;
        MSO(p).first = (struct erl_off_heap_header *) pb;
        pb->val = result_bin;
        pb->bytes = (byte *) result_bin->orig_bytes;
        pb->flags = 0;
        OH_OVERHEAD(&(MSO(p)), pb->size / sizeof (Eterm));
        if (context_b && erts_refc_read(&context_b->intern.refc, 0) == 0) {
            erts_bin_free(context_b);
        }
        return make_binary(pb);
    }
}

#define ENC_TERM		((Eterm) 0)
#define ENC_ARRAY_ELEMENT	((Eterm) 1)
#define ENC_OBJECT_ELEMENT	((Eterm) 2)
// #define ENC_BIN_COPY		((Eterm) 3)
// #define ENC_MAP_PAIR		((Eterm) 4)
// #define ENC_HASHMAP_NODE	((Eterm) 5)

#if 0
static byte*
enc_json(Eterm obj, byte* ep, Uint32 flags)
{
    byte *res;
    (void) enc_json_int(NULL, obj, ep, flags, NULL, &res);
    return res;
}
#endif

/* Interruptable JSON encoder.  Returns 0 when term is completely encoded, or
   -1 when out of reductions. */

static int
enc_json_int(TTBEncodeContext* ctx, Eterm obj, byte* ep, Uint32 dflags, Sint *reds_arg, Binary **result_bin_arg)
{
    WSTACK_DECLARE(s);
    Sint reds = 0;
    byte *endp = (byte *) (*result_bin_arg)->orig_bytes + (*result_bin_arg)->orig_size;

    if (ctx) {
        WSTACK_CHANGE_ALLOCATOR(s, ERTS_ALC_T_SAVED_ESTACK);
        reds = *reds_arg;

        if (ctx->wstack.wstart) { /* restore saved stacks and byte pointer */
            WSTACK_RESTORE(s, &ctx->wstack);
            ep = ctx->ep;
            obj = ctx->obj;
            if (is_non_value(obj)) {
                goto outer_loop;
            }
        }
    }


#define ENSURE_BUFFER(n)						\
    do {								\
        Uint needed_bytes = (n);					\
        if (ep + needed_bytes > endp) {					\
            Sint offset = ep - (byte *) (*result_bin_arg)->orig_bytes;	\
            Uint needed_size = offset + needed_bytes;			\
            Uint new_size = (*result_bin_arg)->orig_size;		\
            do { new_size *= 2; } while (new_size < needed_size);	\
            *result_bin_arg = erts_bin_realloc(*result_bin_arg, new_size); \
            ep = (byte *) (*result_bin_arg)->orig_bytes + offset;	\
            endp = (byte *) (*result_bin_arg)->orig_bytes + (*result_bin_arg)->orig_size; \
        }								\
    } while (0)


    goto encode_term;

 outer_loop:
    while (! WSTACK_ISEMPTY(s)) {
        obj = WSTACK_POP(s);

        switch (WSTACK_POP(s)) {
        case ENC_TERM:
            break;
        case ENC_ARRAY_ELEMENT: {
            Eterm* cons;
            Eterm tail;
            int first = 0;
            if (0) {
            encode_array_element:
                first = 1;
            }
            switch (tag_val_def(obj)) {
            case NIL_DEF:
                ENSURE_BUFFER(1);
                *ep++ = ']';
                goto outer_loop;
            case LIST_DEF:
                if (! first) {
                    ENSURE_BUFFER(1);
                    *ep++ = ',';
                }
                cons = list_val(obj);
                tail = CDR(cons);
                obj = CAR(cons);
                WSTACK_PUSH2(s, ENC_ARRAY_ELEMENT, tail);
                goto encode_term;
            }
            goto fail; // Not a proper list.
        }
        case ENC_OBJECT_ELEMENT: {
            int first = 0;
            Eterm* cons;
            Eterm tail;
            Eterm* tuple;
            Uint tuple_len;
            if (0) {
            enc_object_element:
                first = 1;
            }
            switch (tag_val_def(obj)) {
            case NIL_DEF:
                ENSURE_BUFFER(1);
                *ep++ = '}';
                goto outer_loop;
            case LIST_DEF:
                if (! first) {
                    ENSURE_BUFFER(1);
                    *ep++ = ',';
                }
                cons = list_val(obj);
                tail = CDR(cons);
                obj = CAR(cons);
                if (tag_val_def(obj) != TUPLE_DEF) { goto fail; }
                tuple = tuple_val(obj);
                tuple_len = arityval(*tuple);
                if (tuple_len != 2) { goto fail; }
                if (tag_val_def(tuple[1]) != BINARY_DEF) { goto fail; }
                // Encode key, which must be a binary.
                {
                    Eterm key;
                    Uint bitoffs;
                    Uint bitsize;
                    byte* bytes;
                    Uint len;

                    key = tuple[1];
                    ERTS_GET_BINARY_BYTES(key, bytes, bitoffs, bitsize);

                    if (bitsize != 0) { goto fail; }

                    len = binary_size(key);
                    ENSURE_BUFFER(len + 3);

                    *ep++ = '"';
                    copy_binary_to_buffer(ep, 0, bytes, bitoffs, 8 * len);
                    ep += len;
                    *ep++ = '"';
                    *ep++ = ':';
                }

                WSTACK_PUSH2(s, ENC_OBJECT_ELEMENT, tail);
                obj = tuple[2];
                goto encode_term;
            }
            goto fail; // Not a proper list.
        }
#if 0
        case ENC_BIN_COPY: {
            // This is the code that would handle copying long binaries.
            Uint bits = (Uint)obj;
            Uint bitoffs = WSTACK_POP(s);
            byte* bytes = (byte*) WSTACK_POP(s);
            byte* dst = (byte*) WSTACK_POP(s);
            if (bits > reds * (TERM_TO_JSON_MEMCPY_FACTOR * 8)) {
                Uint n = reds * TERM_TO_JSON_MEMCPY_FACTOR;
                WSTACK_PUSH5(s, (UWord)(dst + n), (UWord)(bytes + n), bitoffs,
                             ENC_BIN_COPY, bits - 8*n);
                bits = 8*n;
                copy_binary_to_buffer(dst, 0, bytes, bitoffs, bits);
                obj = THE_NON_VALUE;
                reds = 0; /* yield */
                break;
            } else {
                copy_binary_to_buffer(dst, 0, bytes, bitoffs, bits);
                reds -= bits / (TERM_TO_JSON_MEMCPY_FACTOR * 8);
                goto outer_loop;
            }
        }
#endif
#if 0
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
#endif
        default:
            goto fail;
        }

    encode_term:
        if (ctx && --reds <= 0) {
            *reds_arg = 0;
            ctx->obj = obj;
            ctx->ep = ep;
            WSTACK_SAVE(s, &ctx->wstack);
            return -1;
        }

        // obj contains the next thing to encode.

        switch (tag_val_def(obj)) {
        case NIL_DEF:
            ENSURE_BUFFER(2);
            *ep++ = '['; *ep++ = ']';
            break;

        case ATOM_DEF:
            if      (obj == am_true) {
                ENSURE_BUFFER(4); *ep++ = 't'; *ep++ = 'r'; *ep++ = 'u'; *ep++ = 'e'; }
            else if (obj == am_false) {
                ENSURE_BUFFER(5); *ep++ = 'f'; *ep++ = 'a'; *ep++ = 'l'; *ep++ = 's'; *ep++ = 'e'; }
            else if (obj == am_null) {
            // else if (ERTS_IS_ATOM_STR("null", obj)) {
                ENSURE_BUFFER(4); *ep++ = 'n'; *ep++ = 'u'; *ep++ = 'l'; *ep++ = 'l'; }
            else { goto fail; }
            break;

        case SMALL_DEF: {
            // Emit a small integer.
            Sint val = signed_val(obj);
            ENSURE_BUFFER(30); // 20 chars is enough for -(2^63)-1.
            ep += sprintf((char *) ep, "%lld", (long long) val); // This could probably be made faster.
            break;
        }

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
            goto encode_array_element;

        case TUPLE_DEF: {
            // A single-element tuple containing a list represents a JSON object.
            Eterm* tuple = tuple_val(obj);
            Uint tuple_len = arityval(*tuple);
            if (tuple_len != 1) { goto fail; }
            switch (tag_val_def(tuple[1])) {
            case NIL_DEF:
                ENSURE_BUFFER(2);
                *ep++ = '{'; *ep++ = '}';
                goto outer_loop;
            case LIST_DEF:
                ENSURE_BUFFER(1);
                *ep++ = '{';
                obj = tuple[1];
                goto enc_object_element;
            }
            goto fail;
        }

#if 0
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
#endif

        case FLOAT_DEF: {
            FloatDef f;
            GET_DOUBLE(obj, f);
            ENSURE_BUFFER(24);
            ep += sprintf((char *) ep, "%.15g", f.fd);
            break;
        }

        case BINARY_DEF: {
            Uint bitoffs;
            Uint bitsize;
            byte* bytes;
            Uint len;

            ERTS_GET_BINARY_BYTES(obj, bytes, bitoffs, bitsize);

            if (bitsize != 0) { goto fail; }
            /* Plain old byte-sized binary. */

            len = binary_size(obj);
            ENSURE_BUFFER(len + 2);

            /* if (0 && ctx && len > r * TERM_TO_JSON_MEMCPY_FACTOR) { */
            /* 	WSTACK_PUSH5(s, (UWord)ep, (UWord)bytes, bitoffs, */
            /* 		     ENC_BIN_COPY, 8 * len); */
            /* 	ep += len + 2; */
            /* } else { */
                *ep++ = '"';
                copy_binary_to_buffer(ep, 0, bytes, bitoffs, 8 * len);
                ep += len;
                *ep++ = '"';
            /* } */
            break;
        }

#if 0
        case PID_DEF:
        case EXTERNAL_PID_DEF:
        case REF_DEF:
        case EXTERNAL_REF_DEF:
        case PORT_DEF:
        case EXTERNAL_PORT_DEF:
        case EXPORT_DEF:
        case FUN_DEF:
#endif
        default:
            goto fail;
        }
    }

    DESTROY_WSTACK(s);
    if (ctx) {
        ASSERT(ctx->wstack.wstart == NULL);
        *reds_arg = reds;
    }
    *result_bin_arg = erts_bin_realloc(*result_bin_arg, ep - (byte *) (*result_bin_arg)->orig_bytes);
    return 0;

fail:
    DESTROY_WSTACK(s);
    if (ctx) {
        ASSERT(ctx->wstack.wstart == NULL);
        *reds_arg = reds;
    }
    *result_bin_arg = erts_bin_realloc(*result_bin_arg, ep - (byte *) (*result_bin_arg)->orig_bytes);
    return 1;
}



