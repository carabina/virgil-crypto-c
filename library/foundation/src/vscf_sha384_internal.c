//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_sha384_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_sha384_defs.h"
#include "vscf_hash_info.h"
#include "vscf_hash_info_api.h"
#include "vscf_hash.h"
#include "vscf_hash_api.h"
#include "vscf_hash_stream.h"
#include "vscf_hash_stream_api.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_sha384_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'hash info api'.
//
static const vscf_hash_info_api_t hash_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash_info' MUST be equal to the 'vscf_api_tag_HASH_INFO'.
    //
    vscf_api_tag_HASH_INFO,
    //
    //  Return implemented hash algorithm type.
    //
    (vscf_hash_info_api_alg_fn)vscf_sha384_alg,
    //
    //  Length of the digest (hashing output) in bytes.
    //
    vscf_sha384_DIGEST_LEN,
    //
    //  Block length of the digest function in bytes.
    //
    vscf_sha384_BLOCK_LEN
};

//
//  Configuration of the interface API 'hash api'.
//
static const vscf_hash_api_t hash_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash' MUST be equal to the 'vscf_api_tag_HASH'.
    //
    vscf_api_tag_HASH,
    //
    //  Link to the inherited interface API 'hash info'.
    //
    &hash_info_api,
    //
    //  Calculate hash over given data.
    //
    (vscf_hash_api_hash_fn)vscf_sha384_hash
};

//
//  Configuration of the interface API 'hash stream api'.
//
static const vscf_hash_stream_api_t hash_stream_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash_stream' MUST be equal to the 'vscf_api_tag_HASH_STREAM'.
    //
    vscf_api_tag_HASH_STREAM,
    //
    //  Link to the inherited interface API 'hash info'.
    //
    &hash_info_api,
    //
    //  Start a new hashing.
    //
    (vscf_hash_stream_api_start_fn)vscf_sha384_start,
    //
    //  Add given data to the hash.
    //
    (vscf_hash_stream_api_update_fn)vscf_sha384_update,
    //
    //  Accompilsh hashing and return it's result (a message digest).
    //
    (vscf_hash_stream_api_finish_fn)vscf_sha384_finish
};

//
//  Compile-time known information about 'sha384' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_sha384_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_sha384_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_sha384_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_sha384_init(vscf_sha384_t *sha384) {

    VSCF_ASSERT_PTR(sha384);

    vscf_zeroize(sha384, sizeof(vscf_sha384_t));

    sha384->info = &info;
    sha384->refcnt = 1;

    vscf_sha384_init_ctx(sha384);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_sha384_init()'.
//
VSCF_PUBLIC void
vscf_sha384_cleanup(vscf_sha384_t *sha384) {

    if (sha384 == NULL || sha384->info == NULL) {
        return;
    }

    if (sha384->refcnt == 0) {
        return;
    }

    if (--sha384->refcnt > 0) {
        return;
    }

    vscf_sha384_cleanup_ctx(sha384);

    vscf_zeroize(sha384, sizeof(vscf_sha384_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_sha384_t *
vscf_sha384_new(void) {

    vscf_sha384_t *sha384 = (vscf_sha384_t *) vscf_alloc(sizeof (vscf_sha384_t));
    VSCF_ASSERT_ALLOC(sha384);

    vscf_sha384_init(sha384);

    return sha384;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha384_new()'.
//
VSCF_PUBLIC void
vscf_sha384_delete(vscf_sha384_t *sha384) {

    vscf_sha384_cleanup(sha384);

    if (sha384 && (sha384->refcnt == 0)) {
        vscf_dealloc(sha384);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_sha384_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_sha384_destroy(vscf_sha384_t **sha384_ref) {

    VSCF_ASSERT_PTR(sha384_ref);

    vscf_sha384_t *sha384 = *sha384_ref;
    *sha384_ref = NULL;

    vscf_sha384_delete(sha384);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_sha384_t *
vscf_sha384_shallow_copy(vscf_sha384_t *sha384) {

    // Proxy to the parent implementation.
    return (vscf_sha384_t *)vscf_impl_shallow_copy((vscf_impl_t *)sha384);
}

//
//  Returns instance of the implemented interface 'hash info'.
//
VSCF_PUBLIC const vscf_hash_info_api_t *
vscf_sha384_hash_info_api(void) {

    return &hash_info_api;
}

//
//  Returns instance of the implemented interface 'hash'.
//
VSCF_PUBLIC const vscf_hash_api_t *
vscf_sha384_hash_api(void) {

    return &hash_api;
}

//
//  Return size of 'vscf_sha384_t' type.
//
VSCF_PUBLIC size_t
vscf_sha384_impl_size(void) {

    return sizeof (vscf_sha384_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_sha384_impl(vscf_sha384_t *sha384) {

    VSCF_ASSERT_PTR(sha384);
    return (vscf_impl_t *)(sha384);
}

static const vscf_api_t *
vscf_sha384_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_HASH:
            return (const vscf_api_t *) &hash_api;
        case vscf_api_tag_HASH_INFO:
            return (const vscf_api_t *) &hash_info_api;
        case vscf_api_tag_HASH_STREAM:
            return (const vscf_api_t *) &hash_stream_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
