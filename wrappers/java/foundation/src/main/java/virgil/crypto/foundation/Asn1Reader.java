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
* Provides interface to the ASN.1 reader.
* Note, that all "read" methods move reading position forward.
* Note, that all "get" do not change reading position.
 */
public interface Asn1Reader {

    /*
    * Reset all internal states and prepare to new ASN.1 reading operations.
     */
    void reset(byte[] data) ;

    /*
    * Return last error.
     */
    void error() ;

    /*
    * Get tag of the current ASN.1 element.
     */
    Integer getTag() ;

    /*
    * Get length of the current ASN.1 element.
     */
    Integer getLen() ;

    /*
    * Read ASN.1 type: TAG.
    * Return element length.
     */
    Integer readTag(Integer tag) ;

    /*
    * Read ASN.1 type: INTEGER.
     */
    Integer readInt() ;

    /*
    * Read ASN.1 type: INTEGER.
     */
    Byte readInt8() ;

    /*
    * Read ASN.1 type: INTEGER.
     */
    Short readInt16() ;

    /*
    * Read ASN.1 type: INTEGER.
     */
    Integer readInt32() ;

    /*
    * Read ASN.1 type: INTEGER.
     */
    Long readInt64() ;

    /*
    * Read ASN.1 type: INTEGER.
     */
    Long readUint() ;

    /*
    * Read ASN.1 type: INTEGER.
     */
    Short readUint8() ;

    /*
    * Read ASN.1 type: INTEGER.
     */
    Integer readUint16() ;

    /*
    * Read ASN.1 type: INTEGER.
     */
    Long readUint32() ;

    /*
    * Read ASN.1 type: INTEGER.
     */
    Long readUint64() ;

    /*
    * Read ASN.1 type: BOOLEAN.
     */
    Boolean readBool() ;

    /*
    * Read ASN.1 type: NULL.
     */
    void readNull() ;

    /*
    * Read ASN.1 type: OCTET STRING.
     */
    byte[] readOctetStr() ;

    /*
    * Read ASN.1 type: BIT STRING.
     */
    byte[] readBitstringAsOctetStr() ;

    /*
    * Read ASN.1 type: UTF8String.
     */
    byte[] readUtf8Str() ;

    /*
    * Read ASN.1 type: OID.
     */
    byte[] readOid() ;

    /*
    * Read raw data of given length.
     */
    byte[] readData(Integer len) ;

    /*
    * Read ASN.1 type: CONSTRUCTED | SEQUENCE.
    * Return element length.
     */
    Integer readSequence() ;

    /*
    * Read ASN.1 type: CONSTRUCTED | SET.
    * Return element length.
     */
    Integer readSet() ;
}

