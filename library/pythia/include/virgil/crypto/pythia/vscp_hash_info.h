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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Provide details about implemented hash algorithm.
// --------------------------------------------------------------------------

#ifndef VSCP_HASH_INFO_H_INCLUDED
#define VSCP_HASH_INFO_H_INCLUDED

#include "vscp_library.h"
#include "vscp_impl.h"
#include "vscp_api.h"
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
//  Contains API requirements of the interface 'hash info'.
//
typedef struct vscp_hash_info_api_t vscp_hash_info_api_t;

//
//  Returns constant 'digest len'.
//
VSCP_PUBLIC size_t
vscp_hash_info_digest_len(const vscp_hash_info_api_t *hash_info_api);

//
//  Returns constant 'block len'.
//
VSCP_PUBLIC size_t
vscp_hash_info_block_len(const vscp_hash_info_api_t *hash_info_api);

//
//  Return hash info API, or NULL if it is not implemented.
//
VSCP_PUBLIC const vscp_hash_info_api_t *
vscp_hash_info_api(vscp_impl_t *impl);

//
//  Check if given object implements interface 'hash info'.
//
VSCP_PUBLIC bool
vscp_hash_info_is_implemented(vscp_impl_t *impl);

//
//  Returns interface unique identifier.
//
VSCP_PUBLIC vscp_api_tag_t
vscp_hash_info_api_tag(const vscp_hash_info_api_t *hash_info_api);

//
//  Returns implementation unique identifier.
//
VSCP_PUBLIC vscp_impl_tag_t
vscp_hash_info_impl_tag(const vscp_hash_info_api_t *hash_info_api);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCP_HASH_INFO_H_INCLUDED
//  @end
