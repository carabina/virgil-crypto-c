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
//  This module contains 'pkcs8 der serializer' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_pkcs8_der_serializer.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_oid.h"
#include "vscf_asn1wr.h"
#include "vscf_asn1_tag.h"
#include "vscf_asn1_writer.h"
#include "vscf_pkcs8_der_serializer_defs.h"
#include "vscf_pkcs8_der_serializer_internal.h"

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
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs8_der_serializer_setup_defaults(vscf_pkcs8_der_serializer_t *pkcs8_der_serializer) {

    VSCF_ASSERT_PTR(pkcs8_der_serializer);

    if (NULL == pkcs8_der_serializer->asn1_writer) {
        vscf_pkcs8_der_serializer_take_asn1_writer(pkcs8_der_serializer, vscf_asn1wr_impl(vscf_asn1wr_new()));
    }

    return vscf_SUCCESS;
}

//
//  Calculate buffer size enough to hold serialized public key.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC size_t
vscf_pkcs8_der_serializer_serialized_public_key_len(
        vscf_pkcs8_der_serializer_t *pkcs8_der_serializer, const vscf_impl_t *public_key) {

    VSCF_ASSERT_PTR(pkcs8_der_serializer);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT(vscf_public_key_can_export_public_key(vscf_public_key_api(public_key)));

    size_t wrappedKeyLen = vscf_public_key_exported_public_key_len(public_key);
    size_t len = 1 + 4 +                //  SubjectPublicKeyInfo ::= SEQUENCE {
                 1 + 1 + 32 +           //          algorithm AlgorithmIdentifier,
                 1 + 4 + wrappedKeyLen; //          subjectPublicKey BIT STRING
                                        //  }

    return len;
}

//
//  Serialize given public key to an interchangeable format.
//
//  Precondition: public key must be exportable.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs8_der_serializer_serialize_public_key(
        vscf_pkcs8_der_serializer_t *pkcs8_der_serializer, const vscf_impl_t *public_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(pkcs8_der_serializer);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT(vscf_public_key_can_export_public_key(vscf_public_key_api(public_key)));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_pkcs8_der_serializer_serialized_public_key_len(pkcs8_der_serializer, public_key));
    VSCF_ASSERT_PTR(pkcs8_der_serializer->asn1_writer);

    //  SubjectPublicKeyInfo ::= SEQUENCE {
    //          algorithm AlgorithmIdentifier,
    //          subjectPublicKey BIT STRING
    //  }

    vscf_impl_t *asn1_writer = pkcs8_der_serializer->asn1_writer;
    vscf_asn1_writer_reset(asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t total_count = 0;

    //
    //  Write key
    //
    vsc_buffer_t *exportedKey = vsc_buffer_new_with_capacity(vscf_public_key_exported_public_key_len(public_key));
    vscf_error_t status = vscf_public_key_export_public_key(public_key, exportedKey);

    total_count += vscf_asn1_writer_write_octet_str_as_bitstring(asn1_writer, vsc_buffer_data(exportedKey));

    vsc_buffer_destroy(&exportedKey);

    if (status != vscf_SUCCESS) {
        return status;
    }

    //
    //  Write algorithm
    //
    size_t algorithm_count = 0;
    algorithm_count += vscf_asn1_writer_write_oid(asn1_writer, vscf_oid_from_key_alg(vscf_key_alg(public_key)));
    algorithm_count += vscf_asn1_writer_write_sequence(asn1_writer, algorithm_count);
    total_count += algorithm_count;

    //
    //  Write SubjectPublicKeyInfo
    //
    vscf_asn1_writer_write_sequence(asn1_writer, total_count);

    //
    //  Finalize
    //
    VSCF_ASSERT(vscf_asn1_writer_error(asn1_writer) == vscf_SUCCESS);

    vsc_buffer_inc_used(out, vscf_asn1_writer_finish(asn1_writer));

    return vscf_SUCCESS;
}

//
//  Calculate buffer size enough to hold serialized private key.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC size_t
vscf_pkcs8_der_serializer_serialized_private_key_len(
        vscf_pkcs8_der_serializer_t *pkcs8_der_serializer, const vscf_impl_t *private_key) {

    VSCF_ASSERT_PTR(pkcs8_der_serializer);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT(vscf_private_key_can_export_private_key(vscf_private_key_api(private_key)));


    size_t wrappedKeyLen = vscf_private_key_exported_private_key_len(private_key);
    size_t len = 1 + 4 +                 //  PrivateKeyInfo ::= SEQUENCE {
                 1 + 1 + 1 +             //          version Version,
                 1 + 1 + 32 +            //          privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
                 1 + 5 + wrappedKeyLen + //          privateKey PrivateKey,
                 0;                      //          attributes [0] IMPLICIT Attributes OPTIONAL
                                         //  }

    return len;
}

//
//  Serialize given private key to an interchangeable format.
//
//  Precondition: private key must be exportable.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs8_der_serializer_serialize_private_key(
        vscf_pkcs8_der_serializer_t *pkcs8_der_serializer, const vscf_impl_t *private_key, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(pkcs8_der_serializer);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT(vscf_private_key_can_export_private_key(vscf_private_key_api(private_key)));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >=
                vscf_pkcs8_der_serializer_serialized_private_key_len(pkcs8_der_serializer, private_key));
    VSCF_ASSERT_PTR(pkcs8_der_serializer->asn1_writer);

    //  PrivateKeyInfo ::= SEQUENCE {
    //          version Version,
    //          privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
    //          privateKey PrivateKey,
    //          attributes [0] IMPLICIT Attributes OPTIONAL
    //  }

    vscf_impl_t *asn1_writer = pkcs8_der_serializer->asn1_writer;
    vscf_asn1_writer_reset(asn1_writer, vsc_buffer_unused_bytes(out), vsc_buffer_unused_len(out));
    size_t total_count = 0;

    //
    //  Write key
    //
    vsc_buffer_t *exportedKey = vsc_buffer_new_with_capacity(vscf_private_key_exported_private_key_len(private_key));
    vscf_error_t status = vscf_private_key_export_private_key(private_key, exportedKey);

    total_count += vscf_asn1_writer_write_octet_str(asn1_writer, vsc_buffer_data(exportedKey));

    vsc_buffer_destroy(&exportedKey);

    if (status != vscf_SUCCESS) {
        return status;
    }

    //
    //  Write algorithm
    //
    size_t algorithm_count = 0;
    algorithm_count += vscf_asn1_writer_write_oid(asn1_writer, vscf_oid_from_key_alg(vscf_key_alg(private_key)));
    algorithm_count += vscf_asn1_writer_write_sequence(asn1_writer, algorithm_count);
    total_count += algorithm_count;

    //
    //  Write version
    //
    total_count += vscf_asn1_writer_write_int(asn1_writer, 0);

    //
    //  Write PrivateKeyInfo
    //
    vscf_asn1_writer_write_sequence(asn1_writer, total_count);

    //
    //  Finalize
    //
    VSCF_ASSERT(vscf_asn1_writer_error(asn1_writer) == vscf_SUCCESS);

    vsc_buffer_inc_used(out, vscf_asn1_writer_finish(asn1_writer));

    return vscf_SUCCESS;
}
