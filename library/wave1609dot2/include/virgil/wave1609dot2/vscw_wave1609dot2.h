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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Provide wave1609dot2 implementation based on the Virgil Security.
// --------------------------------------------------------------------------

#ifndef VSCW_WAVE1609DOT2_H_INCLUDED
#define VSCW_WAVE1609DOT2_H_INCLUDED

#include "vscw_library.h"
#include "vscw_error.h"
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
//  Handle 'wave1609dot2' context.
//
typedef struct vscw_wave1609dot2_t vscw_wave1609dot2_t;

//
//  Return size of 'vscw_wave1609dot2_t'.
//
VSCW_PUBLIC size_t
vscw_wave1609dot2_ctx_size(void);

//
//  Perform initialization of pre-allocated context.
//
VSCW_PUBLIC void
vscw_wave1609dot2_init(vscw_wave1609dot2_t *wave1609dot2_ctx);

//
//  Release all inner resources.
//
VSCW_PUBLIC void
vscw_wave1609dot2_cleanup(vscw_wave1609dot2_t *wave1609dot2_ctx);

//
//  Allocate context and perform it's initialization.
//
VSCW_PUBLIC vscw_wave1609dot2_t *
vscw_wave1609dot2_new(void);

//
//  Release all inner resorces and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCW_PUBLIC void
vscw_wave1609dot2_delete(vscw_wave1609dot2_t *wave1609dot2_ctx);

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscw_wave1609dot2_new ()'.
//
VSCW_PUBLIC void
vscw_wave1609dot2_destroy(vscw_wave1609dot2_t **wave1609dot2_ctx_ref);

//
//  Performs global initialization of the wave1609dot2 library.
//  Must be called once for entire application at startup.
//
VSCW_PUBLIC void
vscw_init(void);

//
//  Performs global cleanup of the wave1609dot2 library.
//  Must be called once for entire application before exit.
//
VSCW_PUBLIC void
vscw_cleanup(void);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCW_WAVE1609DOT2_H_INCLUDED
//  @end
