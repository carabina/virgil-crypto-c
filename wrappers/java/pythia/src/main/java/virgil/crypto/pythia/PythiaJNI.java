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

package virgil.crypto.pythia;

import virgil.crypto.common.utils.NativeUtils;

public class PythiaJNI {

    public static final PythiaJNI INSTANCE;

    static {
        NativeUtils.load();
        INSTANCE = new PythiaJNI();
    }

    private PythiaJNI() {
    }

    public native long pythia_new() ;

    public native void pythia_globalInit() ;

    public native void pythia_globalCleanup() ;

    public native Integer pythia_blindedPasswordBufLen() ;

    public native Integer pythia_deblindedPasswordBufLen() ;

    public native Integer pythia_blindingSecretBufLen() ;

    public native Integer pythia_transformationPrivateKeyBufLen() ;

    public native Integer pythia_transformationPublicKeyBufLen() ;

    public native Integer pythia_transformedPasswordBufLen() ;

    public native Integer pythia_transformedTweakBufLen() ;

    public native Integer pythia_proofValueBufLen() ;

    public native Integer pythia_passwordUpdateTokenBufLen() ;

    public native PythiaBlindResult pythia_blind(long cCtx, byte[] password) ;

    public native byte[] pythia_deblind(long cCtx, byte[] transformedPassword, byte[] blindingSecret) ;

    public native PythiaComputeTransformationKeyPairResult pythia_computeTransformationKeyPair(long cCtx, byte[] transformationKeyId, byte[] pythiaSecret, byte[] pythiaScopeSecret) ;

    public native PythiaTransformResult pythia_transform(long cCtx, byte[] blindedPassword, byte[] tweak, byte[] transformationPrivateKey) ;

    public native PythiaProveResult pythia_prove(long cCtx, byte[] transformedPassword, byte[] blindedPassword, byte[] transformedTweak, byte[] transformationPrivateKey, byte[] transformationPublicKey) ;

    public native void pythia_verify(long cCtx, byte[] transformedPassword, byte[] blindedPassword, byte[] tweak, byte[] transformationPublicKey, byte[] proofValueC, byte[] proofValueU) ;

    public native byte[] pythia_getPasswordUpdateToken(long cCtx, byte[] previousTransformationPrivateKey, byte[] newTransformationPrivateKey) ;

    public native byte[] pythia_updateDeblindedWithToken(long cCtx, byte[] deblindedPassword, byte[] passwordUpdateToken) ;
}

