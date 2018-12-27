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
class Asn1ReaderProxy implements Asn1Reader {

    public long cCtx;

    /* Take C context that implements this interface */
    public Asn1ReaderProxy(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /*
    * Reset all internal states and prepare to new ASN.1 reading operations.
     */
    public void reset(byte[] data) {
        FoundationJNI.INSTANCE.asn1Reader_reset(this.cCtx, data);
    }

    /*
    * Return last error.
     */
    public void error() {
        FoundationJNI.INSTANCE.asn1Reader_error(this.cCtx);
    }

    /*
    * Get tag of the current ASN.1 element.
     */
    public Integer getTag() {
        return FoundationJNI.INSTANCE.asn1Reader_getTag(this.cCtx);
    }

    /*
    * Get length of the current ASN.1 element.
     */
    public Integer getLen() {
        return FoundationJNI.INSTANCE.asn1Reader_getLen(this.cCtx);
    }

    /*
    * Read ASN.1 type: TAG.
    * Return element length.
     */
    public Integer readTag(Integer tag) {
        return FoundationJNI.INSTANCE.asn1Reader_readTag(this.cCtx, tag);
    }

    /*
    * Read ASN.1 type: INTEGER.
     */
    public Integer readInt() {
        return FoundationJNI.INSTANCE.asn1Reader_readInt(this.cCtx);
    }

    /*
    * Read ASN.1 type: INTEGER.
     */
    public Byte readInt8() {
        return FoundationJNI.INSTANCE.asn1Reader_readInt8(this.cCtx);
    }

    /*
    * Read ASN.1 type: INTEGER.
     */
    public Short readInt16() {
        return FoundationJNI.INSTANCE.asn1Reader_readInt16(this.cCtx);
    }

    /*
    * Read ASN.1 type: INTEGER.
     */
    public Integer readInt32() {
        return FoundationJNI.INSTANCE.asn1Reader_readInt32(this.cCtx);
    }

    /*
    * Read ASN.1 type: INTEGER.
     */
    public Long readInt64() {
        return FoundationJNI.INSTANCE.asn1Reader_readInt64(this.cCtx);
    }

    /*
    * Read ASN.1 type: INTEGER.
     */
    public Long readUint() {
        return FoundationJNI.INSTANCE.asn1Reader_readUint(this.cCtx);
    }

    /*
    * Read ASN.1 type: INTEGER.
     */
    public Short readUint8() {
        return FoundationJNI.INSTANCE.asn1Reader_readUint8(this.cCtx);
    }

    /*
    * Read ASN.1 type: INTEGER.
     */
    public Integer readUint16() {
        return FoundationJNI.INSTANCE.asn1Reader_readUint16(this.cCtx);
    }

    /*
    * Read ASN.1 type: INTEGER.
     */
    public Long readUint32() {
        return FoundationJNI.INSTANCE.asn1Reader_readUint32(this.cCtx);
    }

    /*
    * Read ASN.1 type: INTEGER.
     */
    public Long readUint64() {
        return FoundationJNI.INSTANCE.asn1Reader_readUint64(this.cCtx);
    }

    /*
    * Read ASN.1 type: BOOLEAN.
     */
    public Boolean readBool() {
        return FoundationJNI.INSTANCE.asn1Reader_readBool(this.cCtx);
    }

    /*
    * Read ASN.1 type: NULL.
     */
    public void readNull() {
        FoundationJNI.INSTANCE.asn1Reader_readNull(this.cCtx);
    }

    /*
    * Read ASN.1 type: OCTET STRING.
     */
    public byte[] readOctetStr() {
        return FoundationJNI.INSTANCE.asn1Reader_readOctetStr(this.cCtx);
    }

    /*
    * Read ASN.1 type: BIT STRING.
     */
    public byte[] readBitstringAsOctetStr() {
        return FoundationJNI.INSTANCE.asn1Reader_readBitstringAsOctetStr(this.cCtx);
    }

    /*
    * Read ASN.1 type: UTF8String.
     */
    public byte[] readUtf8Str() {
        return FoundationJNI.INSTANCE.asn1Reader_readUtf8Str(this.cCtx);
    }

    /*
    * Read ASN.1 type: OID.
     */
    public byte[] readOid() {
        return FoundationJNI.INSTANCE.asn1Reader_readOid(this.cCtx);
    }

    /*
    * Read raw data of given length.
     */
    public byte[] readData(Integer len) {
        return FoundationJNI.INSTANCE.asn1Reader_readData(this.cCtx, len);
    }

    /*
    * Read ASN.1 type: CONSTRUCTED | SEQUENCE.
    * Return element length.
     */
    public Integer readSequence() {
        return FoundationJNI.INSTANCE.asn1Reader_readSequence(this.cCtx);
    }

    /*
    * Read ASN.1 type: CONSTRUCTED | SET.
    * Return element length.
     */
    public Integer readSet() {
        return FoundationJNI.INSTANCE.asn1Reader_readSet(this.cCtx);
    }
}

