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

#include "vsce_phe_hash.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_const.h"

#include <mbedtls/bignum.h>
#include <stdarg.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'phe hash' context.
//
struct vsce_phe_hash_t {
    //
    //  Function do deallocate self context.
    //
    vsce_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;
    //
    //  Dependency to the implementation 'sha512'.
    //
    vscf_sha512_t *sha512;
    //
    //  Dependency to the class 'simple swu'.
    //
    vsce_simple_swu_t *simple_swu;

    mbedtls_ecp_group group;
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_hash_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_hash_init_ctx(vsce_phe_hash_t *phe_hash);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_hash_cleanup_ctx(vsce_phe_hash_t *phe_hash);

static void
vsce_phe_hash_derive_z(vsce_phe_hash_t *phe_hash, vsc_data_t buffer, bool success, mbedtls_mpi *z);

static void
vsce_phe_hash_push_points_to_buffer(vsce_phe_hash_t *phe_hash, vsc_buffer_t *buffer, size_t count, ...);

//
//  Return size of 'vsce_phe_hash_t'.
//
VSCE_PUBLIC size_t
vsce_phe_hash_ctx_size(void) {

    return sizeof(vsce_phe_hash_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_hash_init(vsce_phe_hash_t *phe_hash) {

    VSCE_ASSERT_PTR(phe_hash);

    vsce_zeroize(phe_hash, sizeof(vsce_phe_hash_t));

    phe_hash->refcnt = 1;

    vsce_phe_hash_init_ctx(phe_hash);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_hash_cleanup(vsce_phe_hash_t *phe_hash) {

    if (phe_hash == NULL) {
        return;
    }

    if (phe_hash->refcnt == 0) {
        return;
    }

    if (--phe_hash->refcnt == 0) {
        vsce_phe_hash_cleanup_ctx(phe_hash);

        vsce_phe_hash_release_sha512(phe_hash);
        vsce_phe_hash_release_simple_swu(phe_hash);

        vsce_zeroize(phe_hash, sizeof(vsce_phe_hash_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_hash_t *
vsce_phe_hash_new(void) {

    vsce_phe_hash_t *phe_hash = (vsce_phe_hash_t *) vsce_alloc(sizeof (vsce_phe_hash_t));
    VSCE_ASSERT_ALLOC(phe_hash);

    vsce_phe_hash_init(phe_hash);

    phe_hash->self_dealloc_cb = vsce_dealloc;

    return phe_hash;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCE_PUBLIC void
vsce_phe_hash_delete(vsce_phe_hash_t *phe_hash) {

    if (phe_hash == NULL) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = phe_hash->self_dealloc_cb;

    vsce_phe_hash_cleanup(phe_hash);

    if (phe_hash->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(phe_hash);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_hash_new ()'.
//
VSCE_PUBLIC void
vsce_phe_hash_destroy(vsce_phe_hash_t **phe_hash_ref) {

    VSCE_ASSERT_PTR(phe_hash_ref);

    vsce_phe_hash_t *phe_hash = *phe_hash_ref;
    *phe_hash_ref = NULL;

    vsce_phe_hash_delete(phe_hash);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_hash_t *
vsce_phe_hash_shallow_copy(vsce_phe_hash_t *phe_hash) {

    VSCE_ASSERT_PTR(phe_hash);

    ++phe_hash->refcnt;

    return phe_hash;
}

//
//  Setup dependency to the implementation 'sha512' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_hash_use_sha512(vsce_phe_hash_t *phe_hash, vscf_sha512_t *sha512) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(sha512);
    VSCE_ASSERT_PTR(phe_hash->sha512 == NULL);

    phe_hash->sha512 = vscf_sha512_shallow_copy(sha512);
}

//
//  Setup dependency to the implementation 'sha512' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_hash_take_sha512(vsce_phe_hash_t *phe_hash, vscf_sha512_t *sha512) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(sha512);
    VSCE_ASSERT_PTR(phe_hash->sha512 == NULL);

    phe_hash->sha512 = sha512;
}

//
//  Release dependency to the implementation 'sha512'.
//
VSCE_PUBLIC void
vsce_phe_hash_release_sha512(vsce_phe_hash_t *phe_hash) {

    VSCE_ASSERT_PTR(phe_hash);

    vscf_sha512_destroy(&phe_hash->sha512);
}

//
//  Setup dependency to the class 'simple swu' with shared ownership.
//
VSCE_PUBLIC void
vsce_phe_hash_use_simple_swu(vsce_phe_hash_t *phe_hash, vsce_simple_swu_t *simple_swu) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(simple_swu);
    VSCE_ASSERT_PTR(phe_hash->simple_swu == NULL);

    phe_hash->simple_swu = vsce_simple_swu_shallow_copy(simple_swu);
}

//
//  Setup dependency to the class 'simple swu' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_hash_take_simple_swu(vsce_phe_hash_t *phe_hash, vsce_simple_swu_t *simple_swu) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(simple_swu);
    VSCE_ASSERT_PTR(phe_hash->simple_swu == NULL);

    phe_hash->simple_swu = simple_swu;
}

//
//  Release dependency to the class 'simple swu'.
//
VSCE_PUBLIC void
vsce_phe_hash_release_simple_swu(vsce_phe_hash_t *phe_hash) {

    VSCE_ASSERT_PTR(phe_hash);

    vsce_simple_swu_destroy(&phe_hash->simple_swu);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_hash_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_hash_init_ctx(vsce_phe_hash_t *phe_hash) {

    VSCE_ASSERT_PTR(phe_hash);

    vsce_phe_hash_take_simple_swu(phe_hash, vsce_simple_swu_new());
    vsce_phe_hash_take_sha512(phe_hash, vscf_sha512_new());

    mbedtls_ecp_group_init(&phe_hash->group);

    int mbedtls_status = 0;
    mbedtls_status = mbedtls_ecp_group_load(&phe_hash->group, MBEDTLS_ECP_DP_SECP256R1);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_hash_cleanup_ctx(vsce_phe_hash_t *phe_hash) {

    VSCE_ASSERT_PTR(phe_hash);

    mbedtls_ecp_group_free(&phe_hash->group);
}

VSCE_PUBLIC void
vsce_phe_hash_derive_account_key(vsce_phe_hash_t *phe_hash, const mbedtls_ecp_point *m, vsc_buffer_t *account_key) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(m);
    VSCE_ASSERT(vsc_buffer_len(account_key) == 0);
    VSCE_ASSERT(vsc_buffer_capacity(account_key) >= vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

    byte M_buffer[vsce_phe_common_PHE_POINT_LENGTH];
    vsc_buffer_t M_buf;
    vsc_buffer_init(&M_buf);
    vsc_buffer_use(&M_buf, M_buffer, sizeof(M_buffer));

    size_t olen = 0;
    int mbedtls_status = mbedtls_ecp_point_write_binary(&phe_hash->group, m, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            vsc_buffer_unused_bytes(&M_buf), vsce_phe_common_PHE_POINT_LENGTH);
    vsc_buffer_inc_used(&M_buf, vsce_phe_common_PHE_POINT_LENGTH);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();

    vscf_hkdf_use_hash(hkdf, vscf_sha512_impl(phe_hash->sha512));

    vscf_hkdf_derive(hkdf, vsc_buffer_data(&M_buf), vsc_data_empty(), k_kdf_info_client_key, account_key,
            vsc_buffer_capacity(account_key));

    vsc_buffer_delete(&M_buf);
    vscf_hkdf_destroy(&hkdf);

    vsce_zeroize(M_buffer, sizeof(M_buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_data_to_point(vsce_phe_hash_t *phe_hash, vsc_data_t data, mbedtls_ecp_point *p) {

    VSCE_ASSERT_PTR(phe_hash);

    byte buffer[vscf_sha512_DIGEST_LEN];
    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, sizeof(buffer));

    vscf_sha512_hash(data, &buff);

    mbedtls_mpi t;
    mbedtls_mpi_init(&t);

    vsc_data_t buff_data = vsc_data_slice_beg(vsc_buffer_data(&buff), 0, vsce_phe_common_PHE_HASH_LEN);
    int mbedtls_status = 0;
    mbedtls_status = mbedtls_mpi_read_binary(&t, buff_data.bytes, buff_data.len);
    VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

    vsce_simple_swu_bignum_to_point(phe_hash->simple_swu, &t, p);

    mbedtls_mpi_free(&t);
    vsc_buffer_delete(&buff);
    vsce_zeroize(buffer, sizeof(buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_hc0(vsce_phe_hash_t *phe_hash, vsc_data_t nc, vsc_data_t password, mbedtls_ecp_point *hc0) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(hc0);

    VSCE_ASSERT(nc.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    enum {
        max_length =
                sizeof(k_dhc0) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH + vsce_phe_common_PHE_MAX_PASSWORD_LENGTH
    };

    const size_t length = sizeof(k_dhc0) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH + password.len;

    byte buffer[max_length];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, length);

    memcpy(vsc_buffer_unused_bytes(&buff), k_dhc0, sizeof(k_dhc0));
    vsc_buffer_inc_used(&buff, sizeof(k_dhc0));

    memcpy(vsc_buffer_unused_bytes(&buff), nc.bytes, nc.len);
    vsc_buffer_inc_used(&buff, nc.len);

    memcpy(vsc_buffer_unused_bytes(&buff), password.bytes, password.len);
    vsc_buffer_inc_used(&buff, password.len);

    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vsce_phe_hash_data_to_point(phe_hash, vsc_buffer_data(&buff), hc0);

    vsc_buffer_delete(&buff);
    vsce_zeroize(buffer, sizeof(buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_hc1(vsce_phe_hash_t *phe_hash, vsc_data_t nc, vsc_data_t password, mbedtls_ecp_point *hc1) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(hc1);

    VSCE_ASSERT(nc.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);
    VSCE_ASSERT(password.len > 0);
    VSCE_ASSERT(password.len <= vsce_phe_common_PHE_MAX_PASSWORD_LENGTH);

    enum {
        max_length =
                sizeof(k_dhc1) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH + vsce_phe_common_PHE_MAX_PASSWORD_LENGTH
    };

    const size_t length = sizeof(k_dhc1) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH + password.len;

    byte buffer[max_length];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, length);

    memcpy(vsc_buffer_unused_bytes(&buff), k_dhc1, sizeof(k_dhc1));
    vsc_buffer_inc_used(&buff, sizeof(k_dhc1));

    memcpy(vsc_buffer_unused_bytes(&buff), nc.bytes, nc.len);
    vsc_buffer_inc_used(&buff, nc.len);

    memcpy(vsc_buffer_unused_bytes(&buff), password.bytes, password.len);
    vsc_buffer_inc_used(&buff, password.len);

    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vsce_phe_hash_data_to_point(phe_hash, vsc_buffer_data(&buff), hc1);

    vsc_buffer_delete(&buff);
    vsce_zeroize(buffer, sizeof(buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_hs0(vsce_phe_hash_t *phe_hash, vsc_data_t ns, mbedtls_ecp_point *hs0) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(hs0);

    VSCE_ASSERT(ns.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);

    enum { length = sizeof(k_dhs0) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH };

    byte buffer[length];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, sizeof(buffer));

    memcpy(vsc_buffer_unused_bytes(&buff), k_dhs0, sizeof(k_dhs0));
    vsc_buffer_inc_used(&buff, sizeof(k_dhs0));

    memcpy(vsc_buffer_unused_bytes(&buff), ns.bytes, ns.len);
    vsc_buffer_inc_used(&buff, ns.len);

    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vsce_phe_hash_data_to_point(phe_hash, vsc_buffer_data(&buff), hs0);

    vsc_buffer_delete(&buff);
    vsce_zeroize(buffer, sizeof(buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_hs1(vsce_phe_hash_t *phe_hash, vsc_data_t ns, mbedtls_ecp_point *hs1) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(hs1);

    VSCE_ASSERT(ns.len == vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH);

    enum { length = sizeof(k_dhs1) + vsce_phe_common_PHE_CLIENT_IDENTIFIER_LENGTH };

    byte buffer[length];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, sizeof(buffer));

    memcpy(vsc_buffer_unused_bytes(&buff), k_dhs1, sizeof(k_dhs1));
    vsc_buffer_inc_used(&buff, sizeof(k_dhs1));

    memcpy(vsc_buffer_unused_bytes(&buff), ns.bytes, ns.len);
    vsc_buffer_inc_used(&buff, ns.len);

    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vsce_phe_hash_data_to_point(phe_hash, vsc_buffer_data(&buff), hs1);

    vsc_buffer_delete(&buff);
    vsce_zeroize(buffer, sizeof(buffer));
}

static void
vsce_phe_hash_derive_z(vsce_phe_hash_t *phe_hash, vsc_data_t buffer, bool success, mbedtls_mpi *z) {

    VSCE_ASSERT_PTR(phe_hash);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();

    byte key_buffer[vscf_sha512_DIGEST_LEN];

    vsc_buffer_t key;
    vsc_buffer_init(&key);
    vsc_buffer_use(&key, key_buffer, sizeof(key_buffer));

    vscf_sha512_hash(buffer, &key);

    vscf_hkdf_use_hash(hkdf, vscf_sha512_impl(phe_hash->sha512));

    byte z_buffer[vsce_phe_common_PHE_HASH_LEN];

    vsc_buffer_t z_buff;
    vsc_buffer_init(&z_buff);
    vsc_buffer_use(&z_buff, z_buffer, sizeof(z_buffer));

    do {
        vsc_buffer_reset(&z_buff);
        int mbedtls_status = mbedtls_mpi_copy(z, &phe_hash->group.N);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);

        vsc_data_t domain = success ? k_proof_ok : k_proof_error;

        vscf_hkdf_derive(hkdf, vsc_buffer_data(&key), domain, k_kdf_info_z, &z_buff, vsc_buffer_capacity(&z_buff));

        mbedtls_status = mbedtls_mpi_read_binary(z, vsc_buffer_bytes(&z_buff), vsc_buffer_len(&z_buff));
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
    } while (mbedtls_ecp_check_privkey(&phe_hash->group, z) != 0);

    vscf_hkdf_destroy(&hkdf);

    vsc_buffer_delete(&key);
    vsce_zeroize(key_buffer, sizeof(key_buffer));
    vsc_buffer_delete(&z_buff);
    vsce_zeroize(z_buffer, sizeof(z_buffer));
}

VSCE_PUBLIC void
vsce_phe_hash_hash_z_success(vsce_phe_hash_t *phe_hash, vsc_data_t server_public_key, const mbedtls_ecp_point *c0,
        const mbedtls_ecp_point *c1, const mbedtls_ecp_point *term1, const mbedtls_ecp_point *term2,
        const mbedtls_ecp_point *term3, mbedtls_mpi *z) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);
    VSCE_ASSERT_PTR(term1);
    VSCE_ASSERT_PTR(term2);
    VSCE_ASSERT_PTR(term3);

    byte buffer[vsce_phe_common_PHE_PUBLIC_KEY_LENGTH + 6 * vsce_phe_common_PHE_POINT_LENGTH];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, sizeof(buffer));

    memcpy(vsc_buffer_unused_bytes(&buff), server_public_key.bytes, server_public_key.len);
    vsc_buffer_inc_used(&buff, server_public_key.len);

    vsce_phe_hash_push_points_to_buffer(phe_hash, &buff, 6, &phe_hash->group.G, c0, c1, term1, term2, term3);
    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vsce_phe_hash_derive_z(phe_hash, vsc_buffer_data(&buff), true, z);

    vsc_buffer_delete(&buff);
}

VSCE_PUBLIC void
vsce_phe_hash_hash_z_failure(vsce_phe_hash_t *phe_hash, vsc_data_t server_public_key, const mbedtls_ecp_point *c0,
        const mbedtls_ecp_point *c1, const mbedtls_ecp_point *term1, const mbedtls_ecp_point *term2,
        const mbedtls_ecp_point *term3, const mbedtls_ecp_point *term4, mbedtls_mpi *z) {

    VSCE_ASSERT_PTR(phe_hash);
    VSCE_ASSERT_PTR(c0);
    VSCE_ASSERT_PTR(c1);
    VSCE_ASSERT_PTR(term1);
    VSCE_ASSERT_PTR(term2);
    VSCE_ASSERT_PTR(term3);
    VSCE_ASSERT_PTR(term4);

    byte buffer[vsce_phe_common_PHE_PUBLIC_KEY_LENGTH + 7 * vsce_phe_common_PHE_POINT_LENGTH];

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, buffer, sizeof(buffer));

    memcpy(vsc_buffer_unused_bytes(&buff), server_public_key.bytes, server_public_key.len);
    vsc_buffer_inc_used(&buff, server_public_key.len);

    vsce_phe_hash_push_points_to_buffer(phe_hash, &buff, 7, &phe_hash->group.G, c0, c1, term1, term2, term3, term4);
    VSCE_ASSERT(vsc_buffer_unused_len(&buff) == 0);

    vsce_phe_hash_derive_z(phe_hash, vsc_buffer_data(&buff), false, z);

    vsc_buffer_delete(&buff);
}

static void
vsce_phe_hash_push_points_to_buffer(vsce_phe_hash_t *phe_hash, vsc_buffer_t *buffer, size_t count, ...) {

    va_list points;

    va_start(points, count);

    size_t olen = 0;
    int mbedtls_status = 0;

    for (size_t i = 0; i < count; i++) {
        const mbedtls_ecp_point *p = va_arg(points, const mbedtls_ecp_point *);
        mbedtls_ecp_point_write_binary(&phe_hash->group, p, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                vsc_buffer_unused_bytes(buffer), vsc_buffer_unused_len(buffer));
        vsc_buffer_inc_used(buffer, olen);
        VSCE_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_status);
        VSCE_ASSERT(olen == vsce_phe_common_PHE_POINT_LENGTH);
    }

    va_end(points);
}
