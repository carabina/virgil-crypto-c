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
//  This module contains 'ed25519 private key' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ed25519_private_key.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_ed25519_public_key_defs.h"
#include "vscf_endianness.h"
#include "vscf_random.h"
#include "vscf_ed25519_private_key_defs.h"
#include "vscf_ed25519_private_key_internal.h"

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
//  Note, this method is called automatically when method vscf_ed25519_private_key_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_ed25519_private_key_init_ctx(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_ed25519_private_key_cleanup_ctx(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    vscf_erase(ed25519_private_key->secret_key, ED25519_KEY_LEN);
}

//
//  Return implemented asymmetric key algorithm type.
//
VSCF_PUBLIC vscf_key_alg_t
vscf_ed25519_private_key_alg(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    return vscf_key_alg_ED25519;
}

//
//  Length of the key in bytes.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_key_len(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    return ED25519_KEY_LEN;
}

//
//  Length of the key in bits.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_key_bitlen(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    return (8 * ED25519_KEY_LEN);
}

//
//  Generate new private or secret key.
//  Note, this operation can be slow.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_generate_key(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    VSCF_ASSERT_PTR(ed25519_private_key->random);
    vsc_buffer_t *generated = vsc_buffer_new();
    VSCF_ASSERT_PTR(generated);
    vsc_buffer_use(generated, ed25519_private_key->secret_key, ED25519_KEY_LEN);
    if (vscf_SUCCESS != vscf_random(ed25519_private_key->random, ED25519_KEY_LEN, generated)) {
        vsc_buffer_destroy(&generated);
        return vscf_error_KEY_GENERATION_FAILED;
    }
    vsc_buffer_destroy(&generated);
    return vscf_SUCCESS;
}

//
//  Sign data given private key.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_sign(
        vscf_ed25519_private_key_t *ed25519_private_key, vsc_data_t data, vsc_buffer_t *signature) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    VSCF_ASSERT(vsc_buffer_is_valid(signature));
    VSCF_ASSERT(ED25519_SIG_LEN == vsc_buffer_capacity(signature));
    VSCF_ASSERT_PTR(data.bytes);
    int ret = ed25519_sign(vsc_buffer_unused_bytes(signature), ed25519_private_key->secret_key, data.bytes, data.len);
    VSCF_ASSERT(ret == 0);
    vsc_buffer_inc_used(signature, vscf_ed25519_private_key_signature_len(ed25519_private_key));
    return vscf_SUCCESS;
}

//
//  Return length in bytes required to hold signature.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_signature_len(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    return ED25519_SIG_LEN;
}

//
//  Extract public part of the key.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ed25519_private_key_extract_public_key(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    vscf_ed25519_public_key_t *ed25519_public_key = vscf_ed25519_public_key_new();
    int ret = ed25519_get_pubkey(ed25519_public_key->public_key, ed25519_private_key->secret_key);
    VSCF_ASSERT(ret == 0);
    vscf_ed25519_public_key_t *ed25519_public_key_le = vscf_ed25519_public_key_new();
    vsc_buffer_t *dst = vsc_buffer_new();
    vsc_buffer_use(dst, ed25519_public_key_le->public_key, ED25519_KEY_LEN);
    vscf_endianness_reverse_memcpy(vsc_data(ed25519_public_key->public_key, ED25519_KEY_LEN), dst);
    vsc_buffer_destroy(&dst);
    vscf_ed25519_public_key_delete(ed25519_public_key);
    return vscf_ed25519_public_key_impl(ed25519_public_key_le);
}

//
//  Export private key in the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be exported in format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_export_private_key(vscf_ed25519_private_key_t *ed25519_private_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= ED25519_KEY_LEN);
    vscf_endianness_reverse_memcpy(vsc_data(ed25519_private_key->secret_key, ED25519_KEY_LEN), out);
    return vscf_SUCCESS;
}

//
//  Return length in bytes required to hold exported private key.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_exported_private_key_len(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    return ED25519_KEY_LEN;
}

//
//  Import private key from the binary format.
//
//  Binary format must be defined in the key specification.
//  For instance, RSA private key must be imported from the format defined in
//  RFC 3447 Appendix A.1.2.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_import_private_key(vscf_ed25519_private_key_t *ed25519_private_key, vsc_data_t data) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    VSCF_ASSERT_PTR(data.bytes);
    VSCF_ASSERT(data.len == ED25519_KEY_LEN);
    vsc_buffer_t *dst = vsc_buffer_new();
    vsc_buffer_use(dst, ed25519_private_key->secret_key, ED25519_KEY_LEN);
    vscf_endianness_reverse_memcpy(data, dst);
    vsc_buffer_destroy(&dst);
    return vscf_SUCCESS;
}

//
//  Compute shared key for 2 asymmetric keys.
//  Note, shared key can be used only for symmetric cryptography.
//
VSCF_PUBLIC vscf_error_t
vscf_ed25519_private_key_compute_shared_key(
        vscf_ed25519_private_key_t *ed25519_private_key, const vscf_impl_t *public_key, vsc_buffer_t *shared_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(shared_key));

    vscf_ed25519_public_key_t *ed25519_public_key = (vscf_ed25519_public_key_t *)public_key;
    byte *ptr = vsc_buffer_unused_bytes(shared_key);
    size_t available = vsc_buffer_unused_len(shared_key);
    VSCF_ASSERT_PTR(available >= ED25519_KEY_LEN);
    int ret = curve25519_key_exchange(ptr, ed25519_public_key->public_key, ed25519_private_key->secret_key);
    if (!ret) {
        vscf_ed25519_public_key_delete(ed25519_public_key);
        return vscf_SUCCESS;
    }
    vscf_ed25519_public_key_delete(ed25519_public_key);
    return vscf_error_SHARED_KEY_EXCHANGE_FAILED;
}

//
//  Return number of bytes required to hold shared key.
//
VSCF_PUBLIC size_t
vscf_ed25519_private_key_shared_key_len(vscf_ed25519_private_key_t *ed25519_private_key) {

    VSCF_ASSERT_PTR(ed25519_private_key);
    return ED25519_KEY_LEN;
}
