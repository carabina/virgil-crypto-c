/*
* Copyright (C) 2015-2019 Virgil Security, Inc.
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

public class RsaPublicKey implements Key, Encrypt, Verify, PublicKey {

    public long cCtx;

    /* Create underlying C context. */
    public RsaPublicKey() {
        super();
        this.cCtx = FoundationJNI.INSTANCE.rsaPublicKey_new();
    }

    /*
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public RsaPublicKey(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    public void setHash(Hash hash) {
        /* Java code */
    }

    public void setRandom(Random random) {
        /* Java code */
    }

    public void setAsn1rd(Asn1Reader asn1rd) {
        /* Java code */
    }

    public void setAsn1wr(Asn1Writer asn1wr) {
        /* Java code */
    }

    /*
    * Return implemented asymmetric key algorithm type.
     */
    public KeyAlg alg() {
        return FoundationJNI.INSTANCE.rsaPublicKey_alg(this.cCtx);
    }

    /*
    * Length of the key in bytes.
     */
    public int keyLen() {
        return FoundationJNI.INSTANCE.rsaPublicKey_keyLen(this.cCtx);
    }

    /*
    * Length of the key in bits.
     */
    public int keyBitlen() {
        return FoundationJNI.INSTANCE.rsaPublicKey_keyBitlen(this.cCtx);
    }

    /*
    * Encrypt given data.
     */
    public byte[] encrypt(byte[] data) {
        return FoundationJNI.INSTANCE.rsaPublicKey_encrypt(this.cCtx, data);
    }

    /*
    * Calculate required buffer length to hold the encrypted data.
     */
    public int encryptedLen(int dataLen) {
        return FoundationJNI.INSTANCE.rsaPublicKey_encryptedLen(this.cCtx, dataLen);
    }

    /*
    * Verify data with given public key and signature.
     */
    public boolean verify(byte[] data, byte[] signature) {
        return FoundationJNI.INSTANCE.rsaPublicKey_verify(this.cCtx, data, signature);
    }

    /*
    * Defines whether a public key can be imported or not.
     */
    public boolean getCanImportPublicKey() {
        return true;
    }

    /*
    * Define whether a public key can be exported or not.
     */
    public boolean getCanExportPublicKey() {
        return true;
    }

    /*
    * Export public key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
     */
    public byte[] exportPublicKey() {
        return FoundationJNI.INSTANCE.rsaPublicKey_exportPublicKey(this.cCtx);
    }

    /*
    * Return length in bytes required to hold exported public key.
     */
    public int exportedPublicKeyLen() {
        return FoundationJNI.INSTANCE.rsaPublicKey_exportedPublicKeyLen(this.cCtx);
    }

    /*
    * Import public key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
     */
    public void importPublicKey(byte[] data) {
        FoundationJNI.INSTANCE.rsaPublicKey_importPublicKey(this.cCtx, data);
    }
}

