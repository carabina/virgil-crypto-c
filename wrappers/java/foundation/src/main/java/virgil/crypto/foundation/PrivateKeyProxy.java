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
* Contains private part of the key.
 */
class PrivateKeyProxy implements PrivateKey {

    public long cCtx;

    /* Take C context that implements this interface */
    public PrivateKeyProxy(long cCtx) {
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
    * Define whether a private key can be exported or not.
     */
    public Boolean getCanExportPrivateKey() {
        return FoundationJNI.INSTANCE.privateKey_getCanExportPrivateKey(this.cCtx);
    }

    /*
    * Define whether a private key can be imported or not.
     */
    public Boolean getCanImportPrivateKey() {
        return FoundationJNI.INSTANCE.privateKey_getCanImportPrivateKey(this.cCtx);
    }

    /*
    * Extract public part of the key.
     */
    public PublicKey extractPublicKey() {
        return FoundationJNI.INSTANCE.privateKey_extractPublicKey(this.cCtx);
    }

    /*
    * Export private key in the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be exported in format defined in
    * RFC 3447 Appendix A.1.2.
     */
    public byte[] exportPrivateKey() {
        return FoundationJNI.INSTANCE.privateKey_exportPrivateKey(this.cCtx);
    }

    /*
    * Return length in bytes required to hold exported private key.
     */
    public Integer exportedPrivateKeyLen() {
        return FoundationJNI.INSTANCE.privateKey_exportedPrivateKeyLen(this.cCtx);
    }

    /*
    * Import private key from the binary format.
    *
    * Binary format must be defined in the key specification.
    * For instance, RSA private key must be imported from the format defined in
    * RFC 3447 Appendix A.1.2.
     */
    public void importPrivateKey(byte[] data) {
        FoundationJNI.INSTANCE.privateKey_importPrivateKey(this.cCtx, data);
    }
}

