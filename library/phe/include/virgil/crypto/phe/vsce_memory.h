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
//  Provides configurable memory management model.
// --------------------------------------------------------------------------

#ifndef VSCE_MEMORY_H_INCLUDED
#define VSCE_MEMORY_H_INCLUDED

#include "vsce_library.h"

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
//  Compile-time configuration of the default alloc function.
//
#ifndef VSCE_ALLOC_DEFAULT
#   define VSCE_ALLOC_DEFAULT(size) calloc (1, (size))
#endif

//
//  Compile-time configuration of the default dealloc function.
//
#ifndef VSCE_DEALLOC_DEFAULT
#   define VSCE_DEALLOC_DEFAULT(mem) free ((mem))
#endif

//
//  Allocate required amount of memory by usging current allocation function.
//  Returns NULL if memory allocation fails.
//
VSCE_PUBLIC void *
vsce_alloc(size_t size);

//
//  Deallocate given memory by usging current de-allocation function.
//
VSCE_PUBLIC void
vsce_dealloc(void *mem);

//
//  Change current used memory functions in the runtime.
//
VSCE_PUBLIC void
vsce_set_allocators(vsce_alloc_fn alloc_cb, vsce_dealloc_fn dealloc_cb);

//
//  Zeroize memory.
//  Note, this function can be reduced by compiler during optimization step.
//  For sensitive data erasing use vsce_erase ().
//
VSCE_PUBLIC void
vsce_zeroize(void *mem, size_t size);

//
//  Zeroize memory in a secure manner.
//  Compiler can not reduce this function during optimization step.
//
VSCE_PUBLIC void
vsce_erase(void *mem, size_t size);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCE_MEMORY_H_INCLUDED
//  @end
