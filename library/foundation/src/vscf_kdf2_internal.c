//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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

#include "vscf_kdf2_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_kdf2.h"
#include "vscf_kdf2_impl.h"
#include "vscf_kdf_api.h"
#include "vscf_hash_stream.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configuration of the interface API 'kdf api'.
//
static const vscf_kdf_api_t kdf_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'kdf' MUST be equal to the 'vscf_api_tag_KDF'.
    //
    vscf_api_tag_KDF,
    //
    //  Calculate hash over given data.
    //
    (vscf_kdf_api_derive_fn)vscf_kdf2_derive
};

//
//  Null-terminated array of the implemented 'Interface API' instances.
//
static const vscf_api_t *api_array[] = {
    (const vscf_api_t *)&kdf_api,
    NULL
};

//
//  Compile-time known information about 'kdf2' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_KDF2,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Erase inner state in a secure manner.
    //
    (vscf_impl_cleanup_fn)vscf_kdf2_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_kdf2_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC vscf_error_t
vscf_kdf2_init(vscf_kdf2_impl_t *kdf2_impl) {

    VSCF_ASSERT_PTR (kdf2_impl);
    VSCF_ASSERT_PTR (kdf2_impl->info == NULL);

    kdf2_impl->info = &info;

    return vscf_SUCCESS;
}

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_kdf2_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSCF_PUBLIC void
vscf_kdf2_cleanup(vscf_kdf2_impl_t *kdf2_impl) {

    VSCF_ASSERT_PTR (kdf2_impl);

    if (kdf2_impl->info == NULL) {
        return;
    }

    //   Cleanup dependency: 'hash'.
    if (kdf2_impl->hash) {

        if (kdf2_impl->is_owning_hash) {
            vscf_impl_destroy (&kdf2_impl->hash);

        } else {
            vscf_impl_cleanup (kdf2_impl->hash);
            kdf2_impl->hash = NULL;
        }

        kdf2_impl->is_owning_hash = 0;
    }

    kdf2_impl->info = NULL;
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_kdf2_impl_t *
vscf_kdf2_new(void) {

    vscf_kdf2_impl_t *kdf2_impl = (vscf_kdf2_impl_t *) vscf_alloc (sizeof (vscf_kdf2_impl_t));
    if (NULL == kdf2_impl) {
        return NULL;
    }

    if (vscf_kdf2_init (kdf2_impl) != vscf_SUCCESS) {
        vscf_dealloc(kdf2_impl);
        return NULL;
    }

    return kdf2_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_kdf2_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSCF_PUBLIC void
vscf_kdf2_delete(vscf_kdf2_impl_t *kdf2_impl) {

    if (kdf2_impl) {
        vscf_kdf2_cleanup (kdf2_impl);
        vscf_dealloc (kdf2_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_kdf2_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_kdf2_destroy(vscf_kdf2_impl_t * *kdf2_impl_ref) {

    VSCF_ASSERT_PTR (kdf2_impl_ref);

    vscf_kdf2_impl_t *kdf2_impl = *kdf2_impl_ref;
    *kdf2_impl_ref = NULL;

    vscf_kdf2_delete (kdf2_impl);
}

//
//  Setup dependency to the interface 'hash stream' and keep ownership.
//
VSCF_PUBLIC void
vscf_kdf2_use_hash_stream(vscf_kdf2_impl_t *kdf2_impl, vscf_impl_t *hash) {

    VSCF_ASSERT_PTR (kdf2_impl);
    VSCF_ASSERT_PTR (hash);
    VSCF_ASSERT_PTR (kdf2_impl->hash == NULL);

    VSCF_ASSERT (vscf_hash_stream_is_implemented (hash));

    kdf2_impl->hash = hash;

    kdf2_impl->is_owning_hash = 0;
}

//
//  Setup dependency to the interface 'hash stream' and transfer ownership.
//
VSCF_PUBLIC void
vscf_kdf2_take_hash_stream(vscf_kdf2_impl_t *kdf2_impl, vscf_impl_t * *hash_ref) {

    VSCF_ASSERT_PTR (kdf2_impl);
    VSCF_ASSERT_PTR (hash_ref);
    VSCF_ASSERT_PTR (kdf2_impl->hash == NULL);

    vscf_impl_t *hash = *hash_ref;
    *hash_ref = NULL;
    VSCF_ASSERT_PTR (hash);

    VSCF_ASSERT (vscf_hash_stream_is_implemented (hash));

    kdf2_impl->hash = hash;

    kdf2_impl->is_owning_hash = 1;
}

//
//  Return size of 'vscf_kdf2_impl_t' type.
//
VSCF_PUBLIC size_t
vscf_kdf2_impl_size(void) {

    return sizeof (vscf_kdf2_impl_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_kdf2_impl(vscf_kdf2_impl_t *kdf2_impl) {

    VSCF_ASSERT_PTR (kdf2_impl);
    return (vscf_impl_t *) (kdf2_impl);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end