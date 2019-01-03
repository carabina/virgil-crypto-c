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

package virgil.crypto.phe;

import virgil.crypto.common.utils.NativeUtils;

public class PheJNI {

    public static final PheJNI INSTANCE;

    static {
        NativeUtils.load("vsce_phe");
        INSTANCE = new PheJNI();
    }

    private PheJNI() {
    }

    public native long errorCtx_new() ;

    public native void errorCtx_reset(long cCtx) ;

    public native void errorCtx_error(long cCtx) ;

    public native long pheServer_new() ;

    public native PheServerGenerateServerKeyPairResult pheServer_generateServerKeyPair(long cCtx) ;

    public native Integer pheServer_enrollmentResponseLen(long cCtx) ;

    public native byte[] pheServer_getEnrollment(long cCtx, byte[] serverPrivateKey, byte[] serverPublicKey) ;

    public native Integer pheServer_verifyPasswordResponseLen(long cCtx) ;

    public native byte[] pheServer_verifyPassword(long cCtx, byte[] serverPrivateKey, byte[] serverPublicKey, byte[] verifyPasswordRequest) ;

    public native Integer pheServer_updateTokenLen(long cCtx) ;

    public native PheServerRotateKeysResult pheServer_rotateKeys(long cCtx, byte[] serverPrivateKey) ;

    public native long pheClient_new() ;

    public native void pheClient_setKeys(long cCtx, byte[] clientPrivateKey, byte[] serverPublicKey) ;

    public native byte[] pheClient_generateClientPrivateKey(long cCtx) ;

    public native Integer pheClient_enrollmentRecordLen(long cCtx) ;

    public native PheClientEnrollAccountResult pheClient_enrollAccount(long cCtx, byte[] enrollmentResponse, byte[] password) ;

    public native Integer pheClient_verifyPasswordRequestLen(long cCtx) ;

    public native byte[] pheClient_createVerifyPasswordRequest(long cCtx, byte[] password, byte[] enrollmentRecord) ;

    public native byte[] pheClient_checkResponseAndDecrypt(long cCtx, byte[] password, byte[] enrollmentRecord, byte[] verifyPasswordResponse) ;

    public native PheClientRotateKeysResult pheClient_rotateKeys(long cCtx, byte[] updateToken) ;

    public native byte[] pheClient_updateEnrollmentRecord(long cCtx, byte[] enrollmentRecord, byte[] updateToken) ;
}

