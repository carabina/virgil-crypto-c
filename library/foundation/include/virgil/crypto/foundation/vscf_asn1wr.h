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
//  This module contains 'asn1wr' implementation.
// --------------------------------------------------------------------------

#ifndef VSCF_ASN1WR_H_INCLUDED
#define VSCF_ASN1WR_H_INCLUDED

#include "vscf_library.h"
#include "vscf_impl.h"
#include "vscf_error.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#endif

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
//  Handles implementation details.
//
typedef struct vscf_asn1wr_t vscf_asn1wr_t;

//
//  Return size of 'vscf_asn1wr_t' type.
//
VSCF_PUBLIC size_t
vscf_asn1wr_impl_size(void);

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_asn1wr_impl(vscf_asn1wr_t *asn1wr);

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_asn1wr_init(vscf_asn1wr_t *asn1wr);

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_asn1wr_init()'.
//
VSCF_PUBLIC void
vscf_asn1wr_cleanup(vscf_asn1wr_t *asn1wr);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_asn1wr_t *
vscf_asn1wr_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_asn1wr_new()'.
//
VSCF_PUBLIC void
vscf_asn1wr_delete(vscf_asn1wr_t *asn1wr);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_asn1wr_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_asn1wr_destroy(vscf_asn1wr_t **asn1wr_ref);

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_asn1wr_t *
vscf_asn1wr_shallow_copy(vscf_asn1wr_t *asn1wr);

//
//  Reset all internal states and prepare to new ASN.1 writing operations.
//
VSCF_PUBLIC void
vscf_asn1wr_reset(vscf_asn1wr_t *asn1wr, byte *out, size_t out_len);

//
//  Move written data to the buffer beginning and forbid further operations.
//  Returns written size in bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_finish(vscf_asn1wr_t *asn1wr);

//
//  Return last error.
//
VSCF_PUBLIC vscf_error_t
vscf_asn1wr_error(vscf_asn1wr_t *asn1wr);

//
//  Move writing position backward for the given length.
//  Return current writing position.
//
VSCF_PUBLIC byte *
vscf_asn1wr_reserve(vscf_asn1wr_t *asn1wr, size_t len);

//
//  Write ASN.1 tag.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_tag(vscf_asn1wr_t *asn1wr, int tag);

//
//  Write length of the following data.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_len(vscf_asn1wr_t *asn1wr, size_t len);

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int(vscf_asn1wr_t *asn1wr, int value);

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int8(vscf_asn1wr_t *asn1wr, int8_t value);

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int16(vscf_asn1wr_t *asn1wr, int16_t value);

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int32(vscf_asn1wr_t *asn1wr, int32_t value);

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_int64(vscf_asn1wr_t *asn1wr, int64_t value);

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_uint(vscf_asn1wr_t *asn1wr, unsigned int value);

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_uint8(vscf_asn1wr_t *asn1wr, uint8_t value);

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_uint16(vscf_asn1wr_t *asn1wr, uint16_t value);

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_uint32(vscf_asn1wr_t *asn1wr, uint32_t value);

//
//  Write ASN.1 type: INTEGER.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_uint64(vscf_asn1wr_t *asn1wr, uint64_t value);

//
//  Write ASN.1 type: BOOLEAN.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_bool(vscf_asn1wr_t *asn1wr, bool value);

//
//  Write ASN.1 type: NULL.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_null(vscf_asn1wr_t *asn1wr);

//
//  Write ASN.1 type: OCTET STRING.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_octet_str(vscf_asn1wr_t *asn1wr, vsc_data_t value);

//
//  Write ASN.1 type: BIT STRING with all zero unused bits.
//
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_octet_str_as_bitstring(vscf_asn1wr_t *asn1wr, vsc_data_t value);

//
//  Write raw data directly to the ASN.1 structure.
//  Return count of written bytes.
//  Note, use this method carefully.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_data(vscf_asn1wr_t *asn1wr, vsc_data_t data);

//
//  Write ASN.1 type: UTF8String.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_utf8_str(vscf_asn1wr_t *asn1wr, vsc_data_t value);

//
//  Write ASN.1 type: OID.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_oid(vscf_asn1wr_t *asn1wr, vsc_data_t value);

//
//  Mark previously written data of given length as ASN.1 type: SQUENCE.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_sequence(vscf_asn1wr_t *asn1wr, size_t len);

//
//  Mark previously written data of given length as ASN.1 type: SET.
//  Return count of written bytes.
//
VSCF_PUBLIC size_t
vscf_asn1wr_write_set(vscf_asn1wr_t *asn1wr, size_t len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_ASN1WR_H_INCLUDED
//  @end
