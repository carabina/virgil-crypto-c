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
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#ifndef VSCE_PHE_UTILS_H_INCLUDED
#define VSCE_PHE_UTILS_H_INCLUDED

#include "vsce_library.h"
#include "vsce_phe_common.h"

#include <mbedtls/bignum.h>

#if !VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_impl.h>
#endif

#if VSCE_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_impl.h>
#endif

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'phe utils' context.
//
typedef struct vsce_phe_utils_t vsce_phe_utils_t;

//
//  Return size of 'vsce_phe_utils_t'.
//
VSCE_PUBLIC size_t
vsce_phe_utils_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_utils_init(vsce_phe_utils_t *phe_utils_ctx);

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_utils_cleanup(vsce_phe_utils_t *phe_utils_ctx);

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_utils_t *
vsce_phe_utils_new(void);

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_utils_delete(vsce_phe_utils_t *phe_utils_ctx);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_utils_new ()'.
//
VSCE_PUBLIC void
vsce_phe_utils_destroy(vsce_phe_utils_t **phe_utils_ctx_ref);

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_utils_t *
vsce_phe_utils_copy(vsce_phe_utils_t *phe_utils_ctx);

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_utils_use_random(vsce_phe_utils_t *phe_utils_ctx, vscf_impl_t *random);

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_utils_take_random(vsce_phe_utils_t *phe_utils_ctx, vscf_impl_t *random);

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_utils_release_random(vsce_phe_utils_t *phe_utils_ctx);

VSCE_PUBLIC void
vsce_phe_utils_random_z(vsce_phe_utils_t *phe_utils_ctx, mbedtls_mpi *z);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_PHE_UTILS_H_INCLUDED
//  @end