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
//  Provides compile time knownledge about algorithm.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_cipher_info.h"
#include "vsf_assert.h"
#include "vsf_cipher_info_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Returns constant 'nonce len'.
//
VSF_PUBLIC size_t
vsf_cipher_info_nonce_len(const vsf_cipher_info_api_t* cipher_info_api) {

    VSF_ASSERT_PTR (cipher_info_api);

    return cipher_info_api->nonce_len;
}

//
//  Returns constant 'key len'.
//
VSF_PUBLIC size_t
vsf_cipher_info_key_len(const vsf_cipher_info_api_t* cipher_info_api) {

    VSF_ASSERT_PTR (cipher_info_api);

    return cipher_info_api->key_len;
}

//
//  Returns constant 'key bitlen'.
//
VSF_PUBLIC size_t
vsf_cipher_info_key_bitlen(const vsf_cipher_info_api_t* cipher_info_api) {

    VSF_ASSERT_PTR (cipher_info_api);

    return cipher_info_api->key_bitlen;
}

//
//  Returns constant 'block len'.
//
VSF_PUBLIC size_t
vsf_cipher_info_block_len(const vsf_cipher_info_api_t* cipher_info_api) {

    VSF_ASSERT_PTR (cipher_info_api);

    return cipher_info_api->block_len;
}

//
//  Return cipher info API, or NULL if it is not implemented.
//
VSF_PUBLIC const vsf_cipher_info_api_t*
vsf_cipher_info_api(vsf_impl_t* impl) {

    VSF_ASSERT_PTR (impl);

    const vsf_api_t *api = vsf_impl_api (impl, vsf_api_tag_CIPHER_INFO);
    return (const vsf_cipher_info_api_t *) api;
}

//
//  Check if given object implements interface 'cipher info'.
//
VSF_PUBLIC bool
vsf_cipher_info_is_implemented(vsf_impl_t* impl) {

    VSF_ASSERT_PTR (impl);

    return vsf_impl_api (impl, vsf_api_tag_CIPHER_INFO) != NULL;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end