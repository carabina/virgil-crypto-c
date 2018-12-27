/*
* Copyright (C) 2015-2018 Virgil Security Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

package virgil.crypto.foundation;

import virgil.crypto.common.*;

/*
* Provides interface to the ASN.1 writer.
* Note, elements are written starting from the buffer ending.
* Note, that all "write" methods move writing position backward.
 */
public interface Asn1Writer {

    /*
    * Reset all internal states and prepare to new ASN.1 writing operations.
     */
    void reset(Byte out, Integer outLen) ;

    /*
    * Move written data to the buffer beginning and forbid further operations.
    * Returns written size in bytes.
     */
    Integer finish() ;

    /*
    * Return last error.
     */
    void error() ;

    /*
    * Move writing position backward for the given length.
    * Return current writing position.
     */
    Byte reserve(Integer len) ;

    /*
    * Write ASN.1 tag.
    * Return count of written bytes.
     */
    Integer writeTag(Integer tag) ;

    /*
    * Write length of the following data.
    * Return count of written bytes.
     */
    Integer writeLen(Integer len) ;

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    Integer writeInt(Integer value) ;

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    Integer writeInt8(Byte value) ;

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    Integer writeInt16(Short value) ;

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    Integer writeInt32(Integer value) ;

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    Integer writeInt64(Long value) ;

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    Integer writeUint(Long value) ;

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    Integer writeUint8(Short value) ;

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    Integer writeUint16(Integer value) ;

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    Integer writeUint32(Long value) ;

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    Integer writeUint64(Long value) ;

    /*
    * Write ASN.1 type: BOOLEAN.
    * Return count of written bytes.
     */
    Integer writeBool(Boolean value) ;

    /*
    * Write ASN.1 type: NULL.
     */
    Integer writeNull() ;

    /*
    * Write ASN.1 type: OCTET STRING.
    * Return count of written bytes.
     */
    Integer writeOctetStr(byte[] value) ;

    /*
    * Write ASN.1 type: BIT STRING with all zero unused bits.
    *
    * Return count of written bytes.
     */
    Integer writeOctetStrAsBitstring(byte[] value) ;

    /*
    * Write raw data directly to the ASN.1 structure.
    * Return count of written bytes.
    * Note, use this method carefully.
     */
    Integer writeData(byte[] data) ;

    /*
    * Write ASN.1 type: UTF8String.
    * Return count of written bytes.
     */
    Integer writeUtf8Str(byte[] value) ;

    /*
    * Write ASN.1 type: OID.
    * Return count of written bytes.
     */
    Integer writeOid(byte[] value) ;

    /*
    * Mark previously written data of given length as ASN.1 type: SQUENCE.
    * Return count of written bytes.
     */
    Integer writeSequence(Integer len) ;

    /*
    * Mark previously written data of given length as ASN.1 type: SET.
    * Return count of written bytes.
     */
    Integer writeSet(Integer len) ;
}
