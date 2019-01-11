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
//  This module contains 'sha384' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_sha384.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_sha384_defs.h"
#include "vscf_sha384_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_sha384_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_sha384_init_ctx(vscf_sha384_t *sha384) {

    VSCF_ASSERT_PTR(sha384);

    mbedtls_sha512_init(&sha384->hash_ctx);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_sha384_cleanup_ctx(vscf_sha384_t *sha384) {

    VSCF_ASSERT_PTR(sha384);

    mbedtls_sha512_free(&sha384->hash_ctx);
}

//
//  Return implemented hash algorithm type.
//
VSCF_PUBLIC vscf_hash_alg_t
vscf_sha384_alg(void) {

    return vscf_hash_alg_SHA384;
}

//
//  Calculate hash over given data.
//
VSCF_PUBLIC void
vscf_sha384_hash(vsc_data_t data, vsc_buffer_t *digest) {

    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(digest));
    VSCF_ASSERT(vsc_buffer_unused_len(digest) >= vscf_sha384_DIGEST_LEN);

    const int is384 = 1;
    mbedtls_sha512(data.bytes, data.len, vsc_buffer_unused_bytes(digest), is384);
    vsc_buffer_inc_used(digest, vscf_sha384_DIGEST_LEN);
}

//
//  Start a new hashing.
//
VSCF_PUBLIC void
vscf_sha384_start(vscf_sha384_t *sha384) {

    VSCF_ASSERT_PTR(sha384);

    const int is384 = 1;
    mbedtls_sha512_starts(&sha384->hash_ctx, is384);
}

//
//  Add given data to the hash.
//
VSCF_PUBLIC void
vscf_sha384_update(vscf_sha384_t *sha384, vsc_data_t data) {

    VSCF_ASSERT_PTR(sha384);
    VSCF_ASSERT(vsc_data_is_valid(data));

    mbedtls_sha512_update(&sha384->hash_ctx, data.bytes, data.len);
}

//
//  Accompilsh hashing and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_sha384_finish(vscf_sha384_t *sha384, vsc_buffer_t *digest) {

    VSCF_ASSERT_PTR(sha384);
    VSCF_ASSERT(vsc_buffer_is_valid(digest));
    VSCF_ASSERT(vsc_buffer_unused_len(digest) >= vscf_sha384_DIGEST_LEN);

    mbedtls_sha512_finish(&sha384->hash_ctx, vsc_buffer_unused_bytes(digest));
    vsc_buffer_inc_used(digest, vscf_sha384_DIGEST_LEN);
}
