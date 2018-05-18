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

#include "vsf_kdf1_internal.h"
#include "vsf_memory.h"
#include "vsf_assert.h"
#include "vsf_kdf1.h"
#include "vsf_kdf1_impl.h"
#include "vsf_kdf_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configuration of the interface API 'kdf api'.
//
static const vsf_kdf_api_t kdf_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'kdf' MUST be equal to the 'vsf_api_tag_KDF'.
    //
    vsf_api_tag_KDF,
    //
    //  Calculate hash over given data.
    //
    (vsf_kdf_api_derive_fn) vsf_kdf1_derive
};

//
//  Null-terminated array of the implemented 'Interface API' instances.
//
static const vsf_api_t* api_array[] = {
    (const vsf_api_t*) &kdf_api,
    NULL
};

//
//  Compile-time known information about 'kdf1' implementation.
//
static const vsf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vsf_impl_tag_KDF1,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Erase inner state in a secure manner.
    //
    (vsf_impl_cleanup_fn) vsf_kdf1_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vsf_impl_destroy_fn) vsf_kdf1_destroy
};

//
//  Perform initialization of preallocated implementation context.
//
VSF_PUBLIC void
vsf_kdf1_init (vsf_kdf1_impl_t* kdf1_impl) {

    VSF_ASSERT_PTR (kdf1_impl);
    VSF_ASSERT_PTR (kdf1_impl->info == NULL);

    kdf1_impl->info = &info;
}

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_kdf1_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_kdf1_cleanup (vsf_kdf1_impl_t* kdf1_impl) {

    VSF_ASSERT_PTR (kdf1_impl);

    if (kdf1_impl->info == NULL) {
        return;
    }

    //   Release dependency: 'hash api'.
    if (kdf1_impl->hash_api) {
        kdf1_impl->hash_api = NULL;
    }

    kdf1_impl->info = NULL;
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSF_PUBLIC vsf_kdf1_impl_t*
vsf_kdf1_new (void) {

    vsf_kdf1_impl_t *kdf1_impl = (vsf_kdf1_impl_t *) vsf_alloc (sizeof (vsf_kdf1_impl_t));
    VSF_ASSERT_PTR (kdf1_impl);

    vsf_kdf1_init (kdf1_impl);

    return kdf1_impl;
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_kdf1_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_kdf1_destroy (vsf_kdf1_impl_t** kdf1_impl_ref) {

    VSF_ASSERT_PTR (kdf1_impl_ref);

    vsf_kdf1_impl_t *kdf1_impl = *kdf1_impl_ref;
    *kdf1_impl_ref = NULL;

    if (kdf1_impl) {
        vsf_kdf1_cleanup (kdf1_impl);
        vsf_dealloc (kdf1_impl);
    }
}

//
//  Returns instance of the implemented interface 'kdf'.
//
VSF_PUBLIC const vsf_kdf_api_t*
vsf_kdf1_kdf_api (void) {

    return &kdf_api;
}

//
//  Setup dependency 'hash api' and keep ownership.
//
VSF_PUBLIC void
vsf_kdf1_use_hash_api (vsf_kdf1_impl_t* kdf1_impl, const vsf_hash_api_t* hash_api) {

    VSF_ASSERT_PTR (kdf1_impl);
    VSF_ASSERT_PTR (hash_api);
    VSF_ASSERT_PTR (kdf1_impl->hash_api == NULL);

    kdf1_impl->hash_api = hash_api;
}

//
//  Return size of 'vsf_kdf1_impl_t' type.
//
VSF_PUBLIC size_t
vsf_kdf1_impl_size (void) {

    return sizeof (vsf_kdf1_impl_t);
}

//
//  Cast to the 'vsf_impl_t' type.
//
VSF_PUBLIC vsf_impl_t*
vsf_kdf1_impl (vsf_kdf1_impl_t* kdf1_impl) {

    VSF_ASSERT_PTR (kdf1_impl);
    return (vsf_impl_t *) (kdf1_impl);
}


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end