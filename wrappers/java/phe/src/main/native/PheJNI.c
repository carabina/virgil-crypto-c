#include "PheJNI.h"

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    errorCtx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_errorCtx_1new
  (JNIEnv *jenv, jobject jobj);

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    errorCtx_reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_errorCtx_1reset
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    errorCtx_error
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_errorCtx_1error
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1new
  (JNIEnv *jenv, jobject jobj);

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_generateServerKeyPair
 * Signature: (J)Lvirgil/crypto/phe/PheServerGenerateServerKeyPairResult;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1generateServerKeyPair
    (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
		return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_enrollmentResponseLen
 * Signature: (J)Ljava/lang/Integer;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1enrollmentResponseLen
    (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
		return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_getEnrollment
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1getEnrollment
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jserverPublicKey) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_verifyPasswordResponseLen
 * Signature: (J)Ljava/lang/Integer;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1verifyPasswordResponseLen
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_verifyPassword
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1verifyPassword
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jserverPublicKey, jbyteArray jverifyPasswordRequest) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_updateTokenLen
 * Signature: (J)Ljava/lang/Integer;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1updateTokenLen
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_rotateKeys
 * Signature: (J[B)Lvirgil/crypto/phe/PheServerRotateKeysResult;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1rotateKeys
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1new
  (JNIEnv *jenv, jobject jobj) {
	  vsce_phe_client_t *phe_client = vsce_phe_client_new();
	  return phe_client->c_ctx;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_setKeys
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1setKeys
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jclientPrivateKey, jbyteArray jserverPublicKey) {
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_generateClientPrivateKey
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1generateClientPrivateKey
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_enrollmentRecordLen
 * Signature: (J)Ljava/lang/Integer;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1enrollmentRecordLen
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_enrollAccount
 * Signature: (J[B[B)Lvirgil/crypto/phe/PheClientEnrollAccountResult;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1enrollAccount
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jenrollmentResponse, jbyteArray jpassword) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_verifyPasswordRequestLen
 * Signature: (J)Ljava/lang/Integer;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1verifyPasswordRequestLen
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_createVerifyPasswordRequest
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1createVerifyPasswordRequest
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpassword, jbyteArray jenrollmentRecord) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_checkResponseAndDecrypt
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1checkResponseAndDecrypt
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpassword, jbyteArray jenrollmentRecord, jbyteArray jverifyPasswordResponse) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_rotateKeys
 * Signature: (J[B)Lvirgil/crypto/phe/PheClientRotateKeysResult;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1rotateKeys
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jupdateToken) {
	  return NULL;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_updateEnrollmentRecord
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1updateEnrollmentRecord
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jenrollmentRecord, jbyteArray jupdateToken) {
	  return NULL;
}

