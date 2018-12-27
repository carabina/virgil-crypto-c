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
* This is MbedTLS implementation of ASN.1 writer.
 */
public class Asn1wr implements Asn1Writer {

    public long cCtx;

    /* Create underlying C context. */
    public Asn1wr() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.asn1wr_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public Asn1wr(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /*
    * Reset all internal states and prepare to new ASN.1 writing operations.
     */
    public void reset(Byte out, Integer outLen) {
        FoundationJNI.INSTANCE.asn1wr_reset(this.cCtx, out, outLen);
    }

    /*
    * Move written data to the buffer beginning and forbid further operations.
    * Returns written size in bytes.
     */
    public Integer finish() {
        return FoundationJNI.INSTANCE.asn1wr_finish(this.cCtx);
    }

    /*
    * Return last error.
     */
    public void error() {
        FoundationJNI.INSTANCE.asn1wr_error(this.cCtx);
    }

    /*
    * Move writing position backward for the given length.
    * Return current writing position.
     */
    public Byte reserve(Integer len) {
        return FoundationJNI.INSTANCE.asn1wr_reserve(this.cCtx, len);
    }

    /*
    * Write ASN.1 tag.
    * Return count of written bytes.
     */
    public Integer writeTag(Integer tag) {
        return FoundationJNI.INSTANCE.asn1wr_writeTag(this.cCtx, tag);
    }

    /*
    * Write length of the following data.
    * Return count of written bytes.
     */
    public Integer writeLen(Integer len) {
        return FoundationJNI.INSTANCE.asn1wr_writeLen(this.cCtx, len);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    public Integer writeInt(Integer value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    public Integer writeInt8(Byte value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt8(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    public Integer writeInt16(Short value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt16(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    public Integer writeInt32(Integer value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt32(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    public Integer writeInt64(Long value) {
        return FoundationJNI.INSTANCE.asn1wr_writeInt64(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    public Integer writeUint(Long value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    public Integer writeUint8(Short value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint8(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    public Integer writeUint16(Integer value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint16(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    public Integer writeUint32(Long value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint32(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
     */
    public Integer writeUint64(Long value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUint64(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: BOOLEAN.
    * Return count of written bytes.
     */
    public Integer writeBool(Boolean value) {
        return FoundationJNI.INSTANCE.asn1wr_writeBool(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: NULL.
     */
    public Integer writeNull() {
        return FoundationJNI.INSTANCE.asn1wr_writeNull(this.cCtx);
    }

    /*
    * Write ASN.1 type: OCTET STRING.
    * Return count of written bytes.
     */
    public Integer writeOctetStr(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeOctetStr(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: BIT STRING with all zero unused bits.
    *
    * Return count of written bytes.
     */
    public Integer writeOctetStrAsBitstring(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeOctetStrAsBitstring(this.cCtx, value);
    }

    /*
    * Write raw data directly to the ASN.1 structure.
    * Return count of written bytes.
    * Note, use this method carefully.
     */
    public Integer writeData(byte[] data) {
        return FoundationJNI.INSTANCE.asn1wr_writeData(this.cCtx, data);
    }

    /*
    * Write ASN.1 type: UTF8String.
    * Return count of written bytes.
     */
    public Integer writeUtf8Str(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeUtf8Str(this.cCtx, value);
    }

    /*
    * Write ASN.1 type: OID.
    * Return count of written bytes.
     */
    public Integer writeOid(byte[] value) {
        return FoundationJNI.INSTANCE.asn1wr_writeOid(this.cCtx, value);
    }

    /*
    * Mark previously written data of given length as ASN.1 type: SQUENCE.
    * Return count of written bytes.
     */
    public Integer writeSequence(Integer len) {
        return FoundationJNI.INSTANCE.asn1wr_writeSequence(this.cCtx, len);
    }

    /*
    * Mark previously written data of given length as ASN.1 type: SET.
    * Return count of written bytes.
     */
    public Integer writeSet(Integer len) {
        return FoundationJNI.INSTANCE.asn1wr_writeSet(this.cCtx, len);
    }
}

