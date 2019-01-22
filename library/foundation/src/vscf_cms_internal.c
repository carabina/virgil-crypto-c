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
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_cms_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_cms_defs.h"
#include "vscf_defaults.h"
#include "vscf_defaults_api.h"
#include "vscf_message_info_serializer.h"
#include "vscf_message_info_serializer_api.h"
#include "vscf_asn1_reader.h"
#include "vscf_asn1_writer.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_cms_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'defaults api'.
//
static const vscf_defaults_api_t defaults_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'defaults' MUST be equal to the 'vscf_api_tag_DEFAULTS'.
    //
    vscf_api_tag_DEFAULTS,
    //
    //  Setup predefined values to the uninitialized class dependencies.
    //
    (vscf_defaults_api_setup_defaults_fn)vscf_cms_setup_defaults
};

//
//  Configuration of the interface API 'message info serializer api'.
//
static const vscf_message_info_serializer_api_t message_info_serializer_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'message_info_serializer' MUST be equal to the 'vscf_api_tag_MESSAGE_INFO_SERIALIZER'.
    //
    vscf_api_tag_MESSAGE_INFO_SERIALIZER,
    //
    //  Return buffer size enough to hold serialized message info.
    //
    (vscf_message_info_serializer_api_serialized_len_fn)vscf_cms_serialized_len,
    //
    //  Serialize class "message info".
    //
    (vscf_message_info_serializer_api_serialize_fn)vscf_cms_serialize,
    //
    //  Deserialize class "message info".
    //
    (vscf_message_info_serializer_api_deserialize_fn)vscf_cms_deserialize
};

//
//  Compile-time known information about 'cms' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_cms_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_cms_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_cms_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_cms_init(vscf_cms_t *cms) {

    VSCF_ASSERT_PTR(cms);

    vscf_zeroize(cms, sizeof(vscf_cms_t));

    cms->info = &info;
    cms->refcnt = 1;
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_cms_init()'.
//
VSCF_PUBLIC void
vscf_cms_cleanup(vscf_cms_t *cms) {

    if (cms == NULL || cms->info == NULL) {
        return;
    }

    if (cms->refcnt == 0) {
        return;
    }

    if (--cms->refcnt > 0) {
        return;
    }

    vscf_cms_release_asn1_reader(cms);
    vscf_cms_release_asn1_writer(cms);

    vscf_zeroize(cms, sizeof(vscf_cms_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_cms_t *
vscf_cms_new(void) {

    vscf_cms_t *cms = (vscf_cms_t *) vscf_alloc(sizeof (vscf_cms_t));
    VSCF_ASSERT_ALLOC(cms);

    vscf_cms_init(cms);

    return cms;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_cms_new()'.
//
VSCF_PUBLIC void
vscf_cms_delete(vscf_cms_t *cms) {

    vscf_cms_cleanup(cms);

    if (cms && (cms->refcnt == 0)) {
        vscf_dealloc(cms);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_cms_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_cms_destroy(vscf_cms_t **cms_ref) {

    VSCF_ASSERT_PTR(cms_ref);

    vscf_cms_t *cms = *cms_ref;
    *cms_ref = NULL;

    vscf_cms_delete(cms);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_cms_t *
vscf_cms_shallow_copy(vscf_cms_t *cms) {

    // Proxy to the parent implementation.
    return (vscf_cms_t *)vscf_impl_shallow_copy((vscf_impl_t *)cms);
}

//
//  Return size of 'vscf_cms_t' type.
//
VSCF_PUBLIC size_t
vscf_cms_impl_size(void) {

    return sizeof (vscf_cms_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_cms_impl(vscf_cms_t *cms) {

    VSCF_ASSERT_PTR(cms);
    return (vscf_impl_t *)(cms);
}

//
//  Setup dependency to the interface 'asn1 reader' with shared ownership.
//
VSCF_PUBLIC void
vscf_cms_use_asn1_reader(vscf_cms_t *cms, vscf_impl_t *asn1_reader) {

    VSCF_ASSERT_PTR(cms);
    VSCF_ASSERT_PTR(asn1_reader);
    VSCF_ASSERT_PTR(cms->asn1_reader == NULL);

    VSCF_ASSERT(vscf_asn1_reader_is_implemented(asn1_reader));

    cms->asn1_reader = vscf_impl_shallow_copy(asn1_reader);
}

//
//  Setup dependency to the interface 'asn1 reader' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_cms_take_asn1_reader(vscf_cms_t *cms, vscf_impl_t *asn1_reader) {

    VSCF_ASSERT_PTR(cms);
    VSCF_ASSERT_PTR(asn1_reader);
    VSCF_ASSERT_PTR(cms->asn1_reader == NULL);

    VSCF_ASSERT(vscf_asn1_reader_is_implemented(asn1_reader));

    cms->asn1_reader = asn1_reader;
}

//
//  Release dependency to the interface 'asn1 reader'.
//
VSCF_PUBLIC void
vscf_cms_release_asn1_reader(vscf_cms_t *cms) {

    VSCF_ASSERT_PTR(cms);

    vscf_impl_destroy(&cms->asn1_reader);
}

//
//  Setup dependency to the interface 'asn1 writer' with shared ownership.
//
VSCF_PUBLIC void
vscf_cms_use_asn1_writer(vscf_cms_t *cms, vscf_impl_t *asn1_writer) {

    VSCF_ASSERT_PTR(cms);
    VSCF_ASSERT_PTR(asn1_writer);
    VSCF_ASSERT_PTR(cms->asn1_writer == NULL);

    VSCF_ASSERT(vscf_asn1_writer_is_implemented(asn1_writer));

    cms->asn1_writer = vscf_impl_shallow_copy(asn1_writer);
}

//
//  Setup dependency to the interface 'asn1 writer' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_cms_take_asn1_writer(vscf_cms_t *cms, vscf_impl_t *asn1_writer) {

    VSCF_ASSERT_PTR(cms);
    VSCF_ASSERT_PTR(asn1_writer);
    VSCF_ASSERT_PTR(cms->asn1_writer == NULL);

    VSCF_ASSERT(vscf_asn1_writer_is_implemented(asn1_writer));

    cms->asn1_writer = asn1_writer;
}

//
//  Release dependency to the interface 'asn1 writer'.
//
VSCF_PUBLIC void
vscf_cms_release_asn1_writer(vscf_cms_t *cms) {

    VSCF_ASSERT_PTR(cms);

    vscf_impl_destroy(&cms->asn1_writer);
}

static const vscf_api_t *
vscf_cms_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_DEFAULTS:
            return (const vscf_api_t *) &defaults_api;
        case vscf_api_tag_MESSAGE_INFO_SERIALIZER:
            return (const vscf_api_t *) &message_info_serializer_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end