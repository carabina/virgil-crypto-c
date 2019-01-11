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

#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE VSCF_HASH_STREAM &&VSCF_SHA256
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_hash_stream.h"
#include "vscf_hash_stream_api.h"
#include "vscf_sha256.h"

#include "test_data_sha256.h"


// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


// --------------------------------------------------------------------------
//  Over implementation: 'sha256'.
// --------------------------------------------------------------------------
void
test__is_implemented__sha256__returns_true(void) {
    vscf_impl_t *impl = vscf_sha256_impl(vscf_sha256_new());

    TEST_ASSERT_TRUE(vscf_hash_stream_is_implemented(impl));

    vscf_impl_destroy(&impl);
}

void
test__hash__sha256_vector_1__success(void) {

    vscf_impl_t *impl = vscf_sha256_impl(vscf_sha256_new());
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_hash_stream_start(impl);
    vscf_hash_stream_update(impl, test_sha256_VECTOR_1_INPUT);
    vscf_hash_stream_finish(impl, digest);

    TEST_ASSERT_EQUAL(test_sha256_VECTOR_1_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha256_VECTOR_1_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vsc_buffer_destroy(&digest);
    vscf_impl_destroy(&impl);
}

void
test__hash__sha256_vector_2__success(void) {

    vscf_impl_t *impl = vscf_sha256_impl(vscf_sha256_new());
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_hash_stream_start(impl);
    vscf_hash_stream_update(impl, test_sha256_VECTOR_2_INPUT);
    vscf_hash_stream_finish(impl, digest);

    TEST_ASSERT_EQUAL(test_sha256_VECTOR_2_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha256_VECTOR_2_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vsc_buffer_destroy(&digest);
    vscf_impl_destroy(&impl);
}

void
test__hash__sha256_vector_3__success(void) {

    vscf_impl_t *impl = vscf_sha256_impl(vscf_sha256_new());
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_hash_stream_start(impl);
    vscf_hash_stream_update(impl, test_sha256_VECTOR_3_INPUT);
    vscf_hash_stream_finish(impl, digest);

    TEST_ASSERT_EQUAL(test_sha256_VECTOR_3_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha256_VECTOR_3_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vsc_buffer_destroy(&digest);
    vscf_impl_destroy(&impl);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
//  Entrypoint
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__is_implemented__sha256__returns_true);
    RUN_TEST(test__hash__sha256_vector_1__success);
    RUN_TEST(test__hash__sha256_vector_2__success);
    RUN_TEST(test__hash__sha256_vector_3__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
