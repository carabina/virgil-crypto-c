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
* Contains public part of the key.
 */
class PublicKeyProxy implements PublicKey {

    public long cCtx;

    /* Take C context that implements this interface */
    public PublicKeyProxy(long cCtx) {
        super();
        this.cCtx = cCtx;
    }

    /*
    * Return implemented asymmetric key algorithm type.
     */
    public KeyAlg alg() {
        return FoundationJNI.INSTANCE.key_alg(this.cCtx);
    }

    /*
    * Length of the key in bytes.
     */
    public Integer keyLen() {
        return FoundationJNI.INSTANCE.key_keyLen(this.cCtx);
    }

    /*
    * Length of the key in bits.
     */
    public Integer keyBitlen() {
        return FoundationJNI.INSTANCE.key_keyBitlen(this.cCtx);
    }

    /*
    * Define whether a public key can be exported or not.
     */
    public Boolean getCanExportPublicKey() {
        return FoundationJNI.INSTANCE.publicKey_getCanExportPublicKey(this.cCtx);
    }

    /*
    * Defines whether a public key can be imported or not.
     */
    public Boolean getCanImportPublicKey() {
        return FoundationJNI.INSTANCE.publicKey_getCanImportPublicKey(this.cCtx);
    }

    /*
    * Export public key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be exported in format defined in
    * RFC 3447 Appendix A.1.1.
     */
    public byte[] exportPublicKey() {
        return FoundationJNI.INSTANCE.publicKey_exportPublicKey(this.cCtx);
    }

    /*
    * Return length in bytes required to hold exported public key.
     */
    public Integer exportedPublicKeyLen() {
        return FoundationJNI.INSTANCE.publicKey_exportedPublicKeyLen(this.cCtx);
    }

    /*
    * Import public key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA public key must be imported from the format defined in
    * RFC 3447 Appendix A.1.1.
     */
    public void importPublicKey(byte[] data) {
        FoundationJNI.INSTANCE.publicKey_importPublicKey(this.cCtx, data);
    }
}

