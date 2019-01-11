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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Error context.
//  Can be used for sequential operations, i.e. parsers, to accumulate error.
//  In this way operation is successful if all steps are successful, otherwise
//  last occurred error code can be obtained.
// --------------------------------------------------------------------------

#ifndef VSCR_ERROR_CTX_H_INCLUDED
#define VSCR_ERROR_CTX_H_INCLUDED

#include "vscr_library.h"
#include "vscr_error.h"

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
//  Perform update only if context defined, otherwise log error.
//
#define VSCR_ERROR_CTX_SAFE_UPDATE(CTX, ERR)                        \
    do {                                                            \
        if (NULL != (CTX)) {                                        \
            vscr_error_ctx_update ((CTX), (ERR));                   \
        } else {                                                    \
            /* TODO: Log this error, when logging will be added. */ \
        }                                                           \
    } while (false)

//
//  Handle 'error ctx' context.
//
typedef struct vscr_error_ctx_t vscr_error_ctx_t;
struct vscr_error_ctx_t {
    vscr_error_t error;
};

//
//  Return size of 'vscr_error_ctx_t'.
//
VSCR_PUBLIC size_t
vscr_error_ctx_ctx_size(void);

//
//  Reset context to the "no error" state.
//
VSCR_PUBLIC void
vscr_error_ctx_reset(vscr_error_ctx_t *error_ctx);

//
//  Update context with given error.
//
VSCR_PRIVATE void
vscr_error_ctx_update(vscr_error_ctx_t *error_ctx, vscr_error_t error);

//
//  Reset context to the "no error" state.
//
VSCR_PUBLIC vscr_error_t
vscr_error_ctx_error(const vscr_error_ctx_t *error_ctx);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCR_ERROR_CTX_H_INCLUDED
//  @end
