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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_ED25519_PUBLIC_KEY && VSCF_FAKE_RANDOM && VSCF_RANDOM && VSCF_ENDIANNESS)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_ed25519_public_key.h"
#include "vscf_random.h"
#include "vscf_fake_random.h"

#include "test_data_ed25519.h"


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
//  Test functions.
// --------------------------------------------------------------------------
void
test__ed25519_public_key_key_len__imported_PUBLIC_KEY__returns_32(void) {
    vscf_ed25519_public_key_t *public_key = vscf_ed25519_public_key_new();
    vscf_error_t result = vscf_ed25519_public_key_import_public_key(public_key, test_ed25519_PUBLIC_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);
    TEST_ASSERT_EQUAL(32, vscf_ed25519_public_key_key_len(public_key));
    vscf_ed25519_public_key_destroy(&public_key);
}

void
test__ed25519_public_key_export_public_key__from_imported_PUBLIC_KEY__expected_equal(void) {
    vscf_ed25519_public_key_t *public_key = vscf_ed25519_public_key_new();
    vscf_error_t result = vscf_ed25519_public_key_import_public_key(public_key, test_ed25519_PUBLIC_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);
    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_ed25519_public_key_exported_public_key_len(public_key));
    result = vscf_ed25519_public_key_export_public_key(public_key, exported_key_buf);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, result);
    TEST_ASSERT_EQUAL(test_ed25519_PUBLIC_KEY.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_ed25519_PUBLIC_KEY.bytes, vsc_buffer_bytes(exported_key_buf), vsc_buffer_len(exported_key_buf));
    vsc_buffer_destroy(&exported_key_buf);
    vscf_ed25519_public_key_destroy(&public_key);
}

void
test__ed25519_public_key_verify__with_imported_PUBLIC_KEY_and_DATA_SIGNATURE(void) {
    vscf_ed25519_public_key_t *public_key = vscf_ed25519_public_key_new();
    vscf_error_t result = vscf_ed25519_public_key_import_public_key(public_key, test_ed25519_PUBLIC_KEY_REVERSE);
    VSCF_ASSERT(result == vscf_SUCCESS);
    bool verify_result = vscf_ed25519_public_key_verify(public_key, test_ed25519_MESSAGE, test_ed25519_SIGNATURE);
    //  Check
    TEST_ASSERT_EQUAL(true, verify_result);

    //  Cleanup
    vscf_ed25519_public_key_destroy(&public_key);
}


#endif // TEST_DEPENDENCIES_AVAILABLE

// --------------------------------------------------------------------------
// Entrypoint.
// clang-format off
// --------------------------------------------------------------------------

int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__ed25519_public_key_key_len__imported_PUBLIC_KEY__returns_32);
    RUN_TEST(test__ed25519_public_key_export_public_key__from_imported_PUBLIC_KEY__expected_equal);
    RUN_TEST(test__ed25519_public_key_verify__with_imported_PUBLIC_KEY_and_DATA_SIGNATURE);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
