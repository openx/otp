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

// #define EXTREME_TTB_TRAPPING 1

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
#include "erl_map.h"

typedef struct T2JContext_struct {
    int alive;
    Uint flags;
    byte *ep;
    Eterm obj;
    ErtsWStack wstack;
    Binary *result_bin;
} T2JContext;

static Export term_to_json_trap_export;

// static byte* enc_json(Eterm, byte*, Uint32 flags);
static int enc_json_int(T2JContext *ctx, Eterm obj, byte *ep, Uint32 dflags, Sint *reds_arg, Binary **result_bin_arg);

static BIF_RETTYPE term_to_json_trap_1(BIF_ALIST_1);

static Eterm erts_term_to_json_int(Process* p, Eterm Term, Uint flags, Binary *context_b);

unsigned i64ToAsciiTable(char *dst, int64_t value);
Sint json_enc_unicode(byte *d, byte *s, byte *send);


void erts_init_json(void) {
    erts_init_trap_export(&term_to_json_trap_export,
                          am_erts_internal, am_term_to_json_trap, 1,
                          &term_to_json_trap_1);
}

/**********************************************************************/

/* This function will be called to continue work when term_to_json_1 returns
   via BIF_TRAP1. */
static BIF_RETTYPE term_to_json_trap_1(BIF_ALIST_1)
{
    Eterm *tp = tuple_val(BIF_ARG_1);
    Eterm Term = tp[1];
    Eterm bt = tp[2];
    Binary *context = erts_magic_ref2bin(bt);

    return erts_term_to_json_int(BIF_P, Term, /* TERM_TO_JSON_DFLAGS */ 0, context);
}

HIPE_WRAPPER_BIF_DISABLE_GC(term_to_json, 1)

/* erlang:term_to_json/1 entry point. */
BIF_RETTYPE term_to_json_1(BIF_ALIST_1)
{
    return erts_term_to_json_int(BIF_P, BIF_ARG_1, /* TERM_TO_JSON_DFLAGS */ 0, /* context */ NULL);
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
#ifndef EXTREME_TTB_TRAPPING
#define TERM_TO_JSON_INITIAL_SIZE 4096
#else
#define TERM_TO_JSON_INITIAL_SIZE 20
#endif

#define TERM_TO_JSON_LOOP_FACTOR TERM_TO_BINARY_LOOP_FACTOR
#define TERM_TO_JSON_MEMCPY_FACTOR 8

static int t2j_context_destructor(Binary *context_bin)
{
    T2JContext *context = ERTS_MAGIC_BIN_DATA(context_bin);
    if (context->alive) {
        context->alive = 0;
        DESTROY_SAVED_WSTACK(&context->wstack);
        if (context->result_bin != NULL) { /* Set to NULL if ever made alive! */
            ASSERT(erts_refc_read(&(context->result_bin->intern.refc), 1));
            erts_bin_free(context->result_bin);
            context->result_bin = NULL;
        }
    }
    return 1;
}

#define JSON_YIELD	0
#define JSON_BADARG	1
#define JSON_DONE	2

static BIF_RETTYPE
erts_term_to_json_int(Process* p, Eterm Term, Uint flags, Binary *context_b)
{
#ifndef EXTREME_TTB_TRAPPING
    Sint reds = (Sint) (ERTS_BIF_REDS_LEFT(p) * TERM_TO_JSON_LOOP_FACTOR);
#else
    Sint reds = 4; /* For testing */
#endif
    Sint initial_reds = reds;
    int is_first_call;
    T2JContext context_buf;
    T2JContext *context;
    byte *bytes;

    if (context_b == NULL) {
        // First call; initialize context.
        is_first_call = 1;
        context_buf.alive = 1;
        context_buf.flags = flags;
        context_buf.ep = NULL;
        context_buf.obj = THE_NON_VALUE;
        context_buf.wstack.wstart = NULL;
        context_buf.result_bin = erts_bin_nrml_alloc(TERM_TO_JSON_INITIAL_SIZE);
        context = &context_buf;
    } else {
        is_first_call = 0;
        context = ERTS_MAGIC_BIN_DATA(context_b);
    }

    bytes = (byte *) context->result_bin->orig_bytes;

    flags = context->flags;
    switch (enc_json_int(context, Term, bytes, flags, &reds, &context->result_bin)) {
    case JSON_YIELD: {
        // Ran out of reductions; yield.
        Eterm *hp;
        Eterm c_term;

        if (context_b == NULL) {
            context_b = erts_create_magic_binary(sizeof (TTBContext), t2j_context_destructor);
            context = ERTS_MAGIC_BIN_DATA(context_b);
            memcpy(context, &context_buf, sizeof (TTBContext));
        }
        if (is_first_call) {
            erts_set_gc_state(p, 0);
        }

        hp = HAlloc(p, ERTS_MAGIC_REF_THING_SIZE+3);
        c_term = erts_mk_magic_ref(&hp, &MSO(p), context_b);
        BUMP_ALL_REDS(p);
        BIF_TRAP1(&term_to_json_trap_export, p, TUPLE2(hp, Term, c_term));
    }

    case JSON_BADARG:
        ASSERT(erts_refc_read(&context->result_bin->intern.refc, 1) == 1);
        erts_bin_free(context->result_bin);
        if (context_b && erts_refc_read(&context_b->intern.refc, 0) == 0) {
            erts_bin_free(context_b);
        }

        context->result_bin = NULL;
        if (! is_first_call) {
            erts_set_gc_state(p, 1);
            ERTS_BIF_ERROR_TRAPPED1(p, EXC_BADARG, bif_export[BIF_term_to_json_1], Term);
        } else {
            BIF_ERROR(p, EXC_BADARG);
        }

    case JSON_DONE: {
        // Finished; create return value.
        Binary *result_bin = context->result_bin;
        size_t real_size = result_bin->orig_size;
        ProcBin* pb;

        BUMP_REDS(p, (initial_reds - reds) / TERM_TO_JSON_LOOP_FACTOR);
        context->result_bin = NULL;
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
        if (! is_first_call) {
            erts_set_gc_state(p, 1);
        }
        BIF_RET(make_binary(pb));
    }
    }
    abort();
}

#define ENC_TERM		((Eterm) 0)
#define ENC_ARRAY_ELEMENT	((Eterm) 1)
#define ENC_OBJECT_ELEMENT	((Eterm) 2) // Used for proplist object encoding.
#define ENC_FLATMAP_PAIR	((Eterm) 3) // Used for flatmap object encoding.
#define ENC_HASHMAP_NODE	((Eterm) 4) // Used for HAMT object encoding.
#define ENC_MAP_ATOM_KEY	((Eterm) 5)
#define ENC_MAP_VALUE		((Eterm) 6) // Flags value for object encoding.
#define ENC_MAP_LAST		((Eterm) 7) // Flags end of object encoding.
#define ENC_BIN_COPY		((Eterm) 8)

// Max number of output bytes one Unicode character can expand to: \uXXXX.
#define MAX_UTF8_EXPANSION 6

#define IS_UTF8_CONTINUATION_BYTE(byte) (((byte) & 0xC0) == 0x80)

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
enc_json_int(T2JContext *ctx, Eterm obj, byte *ep, Uint32 dflags, Sint *reds_arg, Binary **result_bin_arg)
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
          enc_array_element:
            switch (tag_val_def(obj)) {
            case NIL_DEF:
                ENSURE_BUFFER(1);
                *ep++ = ']';
                goto outer_loop;
            case LIST_DEF:
                if (ep[-1] != '[') {
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
            // Encodes the proplist JSON object representation.
            Eterm* cons;
            Eterm tail;
            Eterm* tuple;
            Uint tuple_len;
          enc_object_element:
            switch (tag_val_def(obj)) {
            case NIL_DEF:
                ENSURE_BUFFER(1);
                *ep++ = '}';
                goto outer_loop;
            case LIST_DEF:
                if (ep[-1] != '{') {
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
                WSTACK_PUSH4(s, ENC_OBJECT_ELEMENT, tail, ENC_MAP_VALUE, tuple[2]);
                obj = tuple[1];
                // Encode object key.
                switch (tag_val_def(obj)) {
                case BINARY_DEF:	goto encode_term;
                case ATOM_DEF:		goto enc_map_atom_key;
                default:		goto fail;
                }
            }
            goto fail; // Not a proper list.
        }

        case ENC_FLATMAP_PAIR: {
            // Encodes the flatmap map implementation as a JSON object.
            Uint pairs_left = obj;
            Eterm *vptr = (Eterm *) WSTACK_POP(s);
            Eterm *kptr = (Eterm *) WSTACK_POP(s);
            ENSURE_BUFFER(1);
            if (ep[-1] != '{') {
                *ep++ = ',';
            }
            obj = *kptr;
            if (--pairs_left > 0) {
                WSTACK_PUSH4(s, (UWord)(kptr+1), (UWord)(vptr+1), ENC_FLATMAP_PAIR, pairs_left);
            } else {
                WSTACK_PUSH2(s, ENC_MAP_LAST, THE_NON_VALUE);
            }
            WSTACK_PUSH2(s, ENC_MAP_VALUE, *vptr);
            // Encode object key.
            switch (tag_val_def(obj)) {
            case BINARY_DEF:	goto encode_term;
            case ATOM_DEF:	goto enc_map_atom_key;
            default:		goto fail;
            }
            break;
        }

        case ENC_HASHMAP_NODE: {
            if (is_list(obj)) { /* leaf node [K|V] */
                Eterm *cons = list_val(obj);
                WSTACK_PUSH2(s, ENC_MAP_VALUE, CDR(cons));
                obj = CAR(cons);
                if (ep[-1] != '{') {
                    ENSURE_BUFFER(1);
                    *ep++ = ',';
                }
                // Encode object key.
                switch (tag_val_def(obj)) {
                case BINARY_DEF:	goto encode_term;
                case ATOM_DEF:		goto enc_map_atom_key;
                default:		goto fail;
                }
            }
            break;
        }

        case ENC_MAP_ATOM_KEY: {
            // Encode an object key that is an atom.
            Atom *a;
            Sint strlen;
          enc_map_atom_key:
            a = atom_tab(atom_val(obj));
            ENSURE_BUFFER(a->len * MAX_UTF8_EXPANSION + 2);
            *ep++ = '"';
            strlen = json_enc_unicode(ep, a->name, a->name + a->len);
            if (strlen < 0) { goto fail; }
            ep += strlen;
            *ep++ = '"';
            obj = THE_NON_VALUE;
            goto outer_loop;
        }

        case ENC_MAP_VALUE:
            ENSURE_BUFFER(1);
            *ep++ = ':';
            break;

        case ENC_MAP_LAST:
            ENSURE_BUFFER(1);
            *ep++ = '}';
            goto outer_loop;

        case ENC_BIN_COPY: {
            // Encode large binaries in parts.
            Uint len = (Uint) obj;
            byte *aligned_alloc = (byte *) WSTACK_POP(s);
            byte *bytes = (byte *) WSTACK_POP(s);
            Sint strlen;
            if (len > reds * TERM_TO_JSON_MEMCPY_FACTOR) {
                Uint n = reds * TERM_TO_JSON_MEMCPY_FACTOR;
                while (IS_UTF8_CONTINUATION_BYTE(bytes[n]) && n < len) { n++; }
                WSTACK_PUSH4(s, (UWord) (bytes + n), (UWord) aligned_alloc, ENC_BIN_COPY, len - n);

                ENSURE_BUFFER(MAX_UTF8_EXPANSION * n);
                strlen = json_enc_unicode(ep, bytes, bytes + n);
                if (strlen < 0) {
                    if (aligned_alloc != NULL) {
                        erts_free_aligned_binary_bytes_extra(aligned_alloc, ERTS_ALC_T_BINARY_BUFFER);
                    }
                    goto fail;
                }
                ep += strlen;

                obj = THE_NON_VALUE;
                reds = 0; // Yield.
                break;
            } else {
                ENSURE_BUFFER(MAX_UTF8_EXPANSION * len + 1);
                strlen = json_enc_unicode(ep, bytes, bytes + len);
                if (aligned_alloc != NULL) {
                    erts_free_aligned_binary_bytes_extra(aligned_alloc, ERTS_ALC_T_BINARY_BUFFER);
                }
                if (strlen < 0) { goto fail; }
                ep += strlen;
                *ep++ = '"';
                reds -= len / TERM_TO_JSON_MEMCPY_FACTOR;
                goto outer_loop;
            }
        }

        default:
            goto fail;
        }

    encode_term:
        if (ctx && --reds <= 0) {
            *reds_arg = 0;
            ctx->obj = obj;
            ctx->ep = ep;
            WSTACK_SAVE(s, &ctx->wstack);
            return JSON_YIELD;
        }

        // obj contains the next thing to encode.

        switch (tag_val_def(obj)) {
        case NIL_DEF:
            ENSURE_BUFFER(2);
            *ep++ = '['; *ep++ = ']';
            break;

        case ATOM_DEF:
            if      (obj == am_true) {
                ENSURE_BUFFER(4); ep[0] = 't'; ep[1] = 'r'; ep[2] = 'u'; ep[3] = 'e'; ep += 4; }
            else if (obj == am_false) {
                ENSURE_BUFFER(5); ep[0] = 'f'; ep[1] = 'a'; ep[2] = 'l'; ep[3] = 's'; ep[4] = 'e'; ep += 5; }
            else if (obj == am_null) {
            // else if (ERTS_IS_ATOM_STR("null", obj)) {
                ENSURE_BUFFER(4); ep[0] = 'n'; ep[1] = 'u'; ep[2] = 'l'; ep[3] = 'l'; ep += 4; }
            else { goto fail; }
            break;

        case SMALL_DEF: {
            // Emit a small integer.
            Sint val = signed_val(obj);
            ENSURE_BUFFER(22); // 20 chars is enough for -(2^63)-1 == -9223372036854775807.
            ep += i64ToAsciiTable((char *) ep, (long long) val);
            break;
        }

        case BIG_DEF: {
            // Emit a big integer.
            // Each byte turns into at most 3 decimal digits + 1 for sign.
            Uint big_bufsize = big_bytes(obj) * 3 + 1;
            Uint n;
            ENSURE_BUFFER(big_bufsize);
            n = erts_big_to_binary_bytes(obj, (char *) ep, big_bufsize);
            // erts_big_to_binary writes the bytes at the end of the buffer,
            // so shift them to the beginning.
            if (n < big_bufsize) { memmove(ep, ep + big_bufsize - n, n); }
            ep += n;
            break;
        }

        case LIST_DEF:
            ENSURE_BUFFER(1);
            *ep++ = '[';
            goto enc_array_element;

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

        case MAP_DEF:
            // An erlang map is converted to a JSON object.
            if (is_flatmap(obj)) {
                flatmap_t *mp = (flatmap_t *) flatmap_val(obj);
                Uint size = flatmap_get_size(mp);

                ENSURE_BUFFER(2); // Enough for '{', and '}' if map is empty.
                *ep++ = '{';
                if (size > 0) {
                    Eterm *kptr = flatmap_get_keys(mp);
                    Eterm *vptr = flatmap_get_values(mp);
                    WSTACK_PUSH4(s, (UWord) kptr, (UWord) vptr, ENC_FLATMAP_PAIR, size);
                } else {
                    *ep++ = '}';
                }
            } else {
                Uint node_sz;
                Uint *ptr = boxed_val(obj);
                Eterm hdr = *ptr++;
                ASSERT(is_header(hdr));
                ENSURE_BUFFER(1);
                switch (hdr & _HEADER_MAP_SUBTAG_MASK) {
                case HAMT_SUBTAG_HEAD_ARRAY:
                    *ep++ = '{';
                    ptr++; // Skip arity on map HEAD.
                    node_sz = 16;
                    WSTACK_PUSH2(s, ENC_MAP_LAST, THE_NON_VALUE);
                    break;
                case HAMT_SUBTAG_HEAD_BITMAP:
                    *ep++ = '{';
                    ptr++; // Skip arity on map HEAD.
                    WSTACK_PUSH2(s, ENC_MAP_LAST, THE_NON_VALUE);
                    // FALL THROUGH
                case HAMT_SUBTAG_NODE_BITMAP:
                    node_sz = hashmap_bitcount(MAP_HEADER_VAL(hdr));
                    ASSERT(node_sz < 17);
                    break;
                default:
                    erts_exit(ERTS_ERROR_EXIT, "bad header\r\n");
                }
                WSTACK_RESERVE(s, node_sz * 2);
                while (node_sz--) {
                    WSTACK_FAST_PUSH(s, ENC_HASHMAP_NODE);
                    WSTACK_FAST_PUSH(s, *ptr++);
                }
            }
            break;

        case FLOAT_DEF: {
            FloatDef f;
            byte *epp;
            GET_DOUBLE(obj, f);
            ENSURE_BUFFER(24);
            epp = ep;
            ep += sprintf((char *) ep, "%.15g", f.fd);
            // Ensure that a double always contains a decimal point.
            while (epp < ep) {
                const byte c = *epp++;
                if (c == '.' || c == 'e') { goto no_period_needed; }
            }
            *ep++ = '.'; *ep++ = '0';
          no_period_needed:
            break;
        }

        case BINARY_DEF: {
            byte *aligned_alloc = NULL;
            int chunked_conversion;
            Uint bitoffs;
            Uint bitsize;
            byte *bytes;
            Uint len;
            Sint strlen;

            ERTS_GET_BINARY_BYTES(obj, bytes, bitoffs, bitsize);

            if (bitsize != 0) { goto fail; }
            /* Plain old byte-sized binary. */

            len = binary_size(obj);
            chunked_conversion = ctx != NULL && len > reds * TERM_TO_JSON_MEMCPY_FACTOR;
            if (bitoffs % 8 != 0) {
                bytes = erts_get_aligned_binary_bytes_extra(
                    obj, &aligned_alloc,
                    (chunked_conversion ? ERTS_ALC_T_EXT_TERM_DATA : ERTS_ALC_T_TMP),
                    0);
                if (bytes == NULL) { goto fail; }
            }

            if (chunked_conversion) {
                ENSURE_BUFFER(1);
                *ep++ = '"';
            	WSTACK_PUSH4(s, (UWord) bytes, (UWord) aligned_alloc, ENC_BIN_COPY, len);
            } else {
                ENSURE_BUFFER(MAX_UTF8_EXPANSION * len + 2);
                *ep++ = '"';
                strlen = json_enc_unicode(ep, bytes, bytes + len);
                if (aligned_alloc != NULL) {
                    erts_free_aligned_binary_bytes_extra(aligned_alloc, ERTS_ALC_T_TMP);
                }
                if (strlen < 0) { goto fail; }
                ep += strlen;
                *ep++ = '"';
                reds -= len / TERM_TO_JSON_MEMCPY_FACTOR;
            }
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
    return JSON_DONE;

fail:
    DESTROY_WSTACK(s);
    if (ctx) {
        ASSERT(ctx->wstack.wstart == NULL);
        *reds_arg = reds;
    }
    // If we were going to return the partially-encoded JSON we would realloc
    // the buffer here.
    // *result_bin_arg = erts_bin_realloc(*result_bin_arg, ep - (byte *) (*result_bin_arg)->orig_bytes);
    return JSON_BADARG;
}



// From https://www.slideshare.net/andreialexandrescu1/three-optimization-tips-for-c-15708507

#define P01 10
#define P02 100
#define P03 1000
#define P04 10000
#define P05 100000
#define P06 1000000
#define P07 10000000
#define P08 100000000
#define P09 1000000000
#define P10 10000000000
#define P11 100000000000L
#define P12 1000000000000L

u_int32_t digits10(u_int64_t v);
unsigned int u64ToAsciiTable( char *dst, u_int64_t value);

u_int32_t
digits10(u_int64_t v)
{
    if (v < P01) return 1;
    if (v < P02) return 2;
    if (v < P03) return 3;
    if (v < P12) {
        if (v < P08) {
            if (v < P06) {
                if (v < P04) return 4;
                return 5 + (v >= P05);
            }
            return 7 + (v >= P07);
        }
        if (v < P10) {
            return 9 + (v >= P09);
        }
        return 11 + (v >= P11);
    }
    return 12 + digits10(v / P12);
}

unsigned int
u64ToAsciiTable( char *dst, u_int64_t value)
{
    static const char digits[201] =
        "0001020304050607080910111213141516171819"
        "2021222324252627282930313233343536373839"
        "4041424344454647484950515253545556575859"
        "6061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";
    u_int32_t const length = digits10(value);
    u_int32_t next = length - 1;
    while (value >= 100) {
        const int i = (value % 100) * 2;
        value /= 100;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
        next -= 2;
    }
    // Handle last 1-2 digits.
    if (value < 10) {
        dst[next] = '0' + (u_int32_t) value;
    } else {
        const int i = (u_int32_t) value * 2;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
    }
    return length;
}

unsigned
i64ToAsciiTable(char *dst, int64_t value)
{
    if (value < 0) {
        *dst++ = '-';
        return 1 + u64ToAsciiTable(dst, -value);
    } else {
        return u64ToAsciiTable(dst, value);
    }
}

#define U4 0	 		// Four-byte Unicode.
#define U3 1			// Three-byte Unicode.
#define U2 2			// Two-byte Unicode.
#define A  3			// Safe ASCII.
// #define E2 0			// Escape with backslash.
#define E6 4			// Escape as "\uHHHH".
#define C  5			// Unicode continuation.
#define B  6			// Bad character.

static const byte unicode_enc_map[] = {
//   0    1    2    3    4    5    6    7     8    9    A    B    C    D    E    F
    E6,	 E6,  E6,  E6,  E6,  E6,  E6,  E6,  'b', 't', 'n',  E6,	 E6, 'r',  E6,  E6, // 0_
    E6,	 E6,  E6,  E6,  E6,  E6,  E6,  E6,   E6,  E6,  E6,  E6,	 E6,  E6,  E6,  E6, // 1_
     A,	  A, '"',   A,   A,   A,   A,   A,    A,   A,   A,   A,	  A,   A,   A,   A, // 2_
     A,	  A,   A,   A,   A,   A,   A,   A,    A,   A,   A,   A,	  A,   A,   A,   A, // 3_

     A,	  A,   A,   A,   A,   A,   A,   A,    A,   A,   A,   A,	  A,   A,   A,   A, // 4_
     A,	  A,   A,   A,   A,   A,   A,   A,    A,   A,   A,   A,'\\',   A,   A,   A, // 5_
     A,	  A,   A,   A,   A,   A,   A,   A,    A,   A,   A,   A,	  A,   A,   A,   A, // 6_
     A,	  A,   A,   A,   A,   A,   A,   A,    A,   A,   A,   A,	  A,   A,   A,  E6, // 7_

     B,	  B,   C,   C,   C,   C,   C,   C,    C,   C,   C,   C,	  C,   C,   C,   C, // 8_
     C,	  C,   C,   C,   C,   C,   C,   C,    C,   C,   C,   C,	  C,   C,   C,   C, // 9_
     C,	  C,   C,   C,   C,   C,   C,   C,    C,   C,   C,   C,	  C,   C,   C,   C, // A_
     C,	  C,   C,   C,   C,   C,   C,   C,    C,   C,   C,   C,	  C,   C,   C,   C, // B_

    U2,	 U2,  U2,  U2,  U2,  U2,  U2,  U2,   U2,  U2,  U2,  U2,	 U2,  U2,  U2,  U2, // C_
    U2,	 U2,  U2,  U2,  U2,  U2,  U2,  U2,   U2,  U2,  U2,  U2,	 U2,  U2,  U2,  U2, // D_
    U3,	 U3,  U3,  U3,  U3,  U3,  U3,  U3,   U3,  U3,  U3,  U3,	 U3,  U3,  U3,  U3, // E_
    U4,	 U4,  U4,  U4,  U4,   B,   B,   B,    B,   B,   B,   B,	  B,   B,   B,   B, // F_
};

byte *json_encode_byte(byte *d, int ucs);

byte *
json_encode_byte(byte *d, int ucs)
{
    const int low = (ucs >> 4) && 0xf;
    const int high = ucs && 0xf;
    *d++ = '0';
    *d++ = '0';
    *d++ = (low  < 10 ? '0' : ('A' - 10)) + low;
    *d++ = (high < 10 ? '0' : ('A' - 10)) + high;
    return d;
}

Sint
json_enc_unicode(byte *d, byte *s, byte *send)
{
    const byte *dstart = d;
    while (s < send) {
        const byte code = unicode_enc_map[*s];
        switch (code) {
        case U4: *d++ = *s++; // FALL THROUGH
        case U3: *d++ = *s++; // FALL THROUGH
        case U2: *d++ = *s++; // FALL THROUGH
        case A:  *d++ = *s++; continue;
        case E6: *d++ = '\\'; *d++ = 'u'; d = json_encode_byte(d, *s++); continue;
        case B: return -1;
        case C: return -1;
        default: *d++ = '\\'; *d++ = code; s++; continue;
        }
    }
    return d - dstart;
}
