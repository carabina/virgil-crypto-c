#include <stdio.h>
#include <virgil/crypto/phe/vsce_phe_cipher.h>
#include <virgil/crypto/phe/vsce_phe_client.h>
#include <virgil/crypto/phe/vsce_phe_server.h>
#include "virgil_crypto_phe_PheJNI.h"

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    errorCtx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_errorCtx_1new
  (JNIEnv *jenv, jobject jobj);

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    errorCtx_close
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_errorCtx_1close
  (JNIEnv *jenv, jobject jobj, jlong c_ctx);

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
  (JNIEnv *jenv, jobject jobj) {
	  return vsce_phe_server_new();
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_close
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1close
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
	  vsce_phe_server_delete(c_ctx);
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_generateServerKeyPair
 * Signature: (J)Lvirgil/crypto/phe/PheServerGenerateServerKeyPairResult;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1generateServerKeyPair
    (JNIEnv *jenv, jobject jobj, jlong c_ctx) {

  vsc_buffer_t *server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
  vsc_buffer_t *server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

  vsce_phe_server_generate_server_key_pair(c_ctx, server_private_key, server_public_key);

  // Create result class
  jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/phe/PheServerGenerateServerKeyPairResult");
  if (NULL == cls) {
    printf("Class PheServerGenerateServerKeyPairResult not found.\n");
    return NULL;
  }
  jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
  jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
  
  // Set private key
  jfieldID fidPrivateKey = (*jenv)->GetFieldID(jenv, cls, "serverPrivateKey", "[B");
  jbyteArray jprivArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(server_private_key));
  (*jenv)->SetByteArrayRegion (jenv, jprivArr, 0, vsc_buffer_len(server_private_key), vsc_buffer_bytes(server_private_key));
  (*jenv)->SetObjectField(jenv, newObj, fidPrivateKey, jprivArr);
  
  // Set public key
  jfieldID fidPublicKey = (*jenv)->GetFieldID(jenv, cls, "serverPublicKey", "[B");
  jbyteArray jPubArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(server_public_key));
  (*jenv)->SetByteArrayRegion (jenv, jPubArr, 0, vsc_buffer_len(server_public_key), vsc_buffer_bytes(server_public_key));
  (*jenv)->SetObjectField(jenv, newObj, fidPublicKey, jPubArr);

  // Free resources
  vsc_buffer_delete(server_private_key);
  vsc_buffer_delete(server_public_key);
  
  return newObj;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_enrollmentResponseLen
  * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1enrollmentResponseLen
    (JNIEnv *jenv, jobject jobj, jlong c_ctx) {

  return 0;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_getEnrollment
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1getEnrollment
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jserverPublicKey) {

  vsc_data_t server_private_key = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

  vsc_data_t server_public_key = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jserverPublicKey));

  //  Allocate output buffer for output 'enrollment_response'
  vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len(c_ctx));
  
  vsce_error_t status = vsce_phe_server_get_enrollment(c_ctx, server_private_key, server_public_key, enrollment_response);

  //TODO Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }
  
  jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(enrollment_response));
  (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(enrollment_response), vsc_buffer_bytes(enrollment_response));

  // Free resources
  vsc_buffer_delete(enrollment_response);

  return ret;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_verifyPasswordResponseLen
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1verifyPasswordResponseLen
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {

  return 0;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_verifyPassword
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1verifyPassword
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey, jbyteArray jserverPublicKey, jbyteArray jverifyPasswordRequest) {

  vsc_data_t server_private_key = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jserverPrivateKey));
    
  vsc_data_t server_public_key = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jserverPublicKey));

  vsc_data_t verify_password_request = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jverifyPasswordRequest, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jverifyPasswordRequest));

  vsc_buffer_t *verify_password_response = vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len(c_ctx));

  vsce_error_t status = vsce_phe_server_verify_password(c_ctx, server_private_key, server_public_key, verify_password_request, verify_password_response);

  //TODO Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }
  
  jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(verify_password_response));
  (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(verify_password_response), vsc_buffer_bytes(verify_password_response));

  // Free resources
  vsc_buffer_delete(verify_password_response);

  return ret;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_updateTokenLen
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1updateTokenLen
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {

  return 0;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheServer_rotateKeys
 * Signature: (J[B)Lvirgil/crypto/phe/PheServerRotateKeysResult;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheServer_1rotateKeys
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jserverPrivateKey) {

  vsc_data_t server_private_key = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jserverPrivateKey, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jserverPrivateKey));

  vsc_buffer_t *new_server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
  vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
  vsc_buffer_t *update_token = vsc_buffer_new_with_capacity(vsce_phe_server_update_token_len(c_ctx));

  vsce_error_t status = vsce_phe_server_rotate_keys(c_ctx, server_private_key, new_server_private_key, new_server_public_key, update_token);
  
  //TODO Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }

  // Create result class
  jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/phe/PheServerRotateKeysResult");
  if (NULL == cls) {
    printf("Class PheServerRotateKeysResult not found.\n");
    return NULL;
  }
  jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
  jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
  
  // Set new private key
  jfieldID fidNewPrivateKey = (*jenv)->GetFieldID(jenv, cls, "newServerPrivateKey", "[B");
  jbyteArray jnewPrivArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_private_key));
  (*jenv)->SetByteArrayRegion (jenv, jnewPrivArr, 0, vsc_buffer_len(new_server_private_key), vsc_buffer_bytes(new_server_private_key));
  (*jenv)->SetObjectField(jenv, newObj, fidNewPrivateKey, jnewPrivArr);
  
  // Set new public key
  jfieldID fidNewPublicKey = (*jenv)->GetFieldID(jenv, cls, "newServerPublicKey", "[B");
  jbyteArray jNewPubArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_public_key));
  (*jenv)->SetByteArrayRegion (jenv, jNewPubArr, 0, vsc_buffer_len(new_server_public_key), vsc_buffer_bytes(new_server_public_key));
  (*jenv)->SetObjectField(jenv, newObj, fidNewPublicKey, jNewPubArr);
  
  // Set update token
  jfieldID fidUpdateToken = (*jenv)->GetFieldID(jenv, cls, "updateToken", "[B");
  jbyteArray jUpdateTokenArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(update_token));
  (*jenv)->SetByteArrayRegion (jenv, jUpdateTokenArr, 0, vsc_buffer_len(update_token), vsc_buffer_bytes(update_token));
  (*jenv)->SetObjectField(jenv, newObj, fidUpdateToken, jUpdateTokenArr);

  // Free resources
  vsc_buffer_delete(new_server_private_key);
  vsc_buffer_delete(new_server_public_key);
  vsc_buffer_delete(update_token);
  
  return newObj;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1new
  (JNIEnv *jenv, jobject jobj) {
	  return vsce_phe_client_new();
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_close
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1close
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {
	  vsce_phe_client_delete(c_ctx);
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_setKeys
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1setKeys
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jclientPrivateKey, jbyteArray jserverPublicKey) {

  vsc_data_t client_private_key = vsc_data(
      (*jenv)->GetByteArrayElements(jenv, jclientPrivateKey, JNI_FALSE),
      (*jenv)->GetArrayLength(jenv, jclientPrivateKey));
  
  vsc_data_t server_public_key = vsc_data(
      (*jenv)->GetByteArrayElements(jenv, jserverPublicKey, JNI_FALSE),
      (*jenv)->GetArrayLength(jenv, jserverPublicKey));

  vsce_phe_client_set_keys(c_ctx, client_private_key, server_public_key);
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_generateClientPrivateKey
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1generateClientPrivateKey
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {

  vsc_buffer_t *client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

  vsce_error_t status = vsce_phe_client_generate_client_private_key(c_ctx, client_private_key);

  //TODO  Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }

  jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(client_private_key));
  (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(client_private_key), vsc_buffer_bytes(client_private_key));

  // Free resources
  vsc_buffer_delete(client_private_key);

  return ret;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_enrollmentRecordLen
  * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1enrollmentRecordLen
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {

  return 0;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_enrollAccount
 * Signature: (J[B[B)Lvirgil/crypto/phe/PheClientEnrollAccountResult;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1enrollAccount
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jenrollmentResponse, jbyteArray jpassword) {

  vsc_data_t enrollment_response = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jenrollmentResponse, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jenrollmentResponse));

  vsc_data_t password = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jpassword, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jpassword));

  vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(c_ctx));
  vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

  vsce_error_t status = vsce_phe_client_enroll_account(c_ctx, enrollment_response, password, enrollment_record, account_key);

  //TODO Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }
  
  // Create result class
  jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/phe/PheClientEnrollAccountResult");
  if (NULL == cls) {
    printf("Class PheClientEnrollAccountResult not found.\n");
    return NULL;
  }
  jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
  jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
  
  // Set enrollment record
  jfieldID fidEnrollmentRecord = (*jenv)->GetFieldID(jenv, cls, "enrollmentRecord", "[B");
  jbyteArray jenRecArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(enrollment_record));
  (*jenv)->SetByteArrayRegion (jenv, jenRecArr, 0, vsc_buffer_len(enrollment_record), vsc_buffer_bytes(enrollment_record));
  (*jenv)->SetObjectField(jenv, newObj, fidEnrollmentRecord, jenRecArr);
  
  // Set account key
  jfieldID fidAccountKey = (*jenv)->GetFieldID(jenv, cls, "accountKey", "[B");
  jbyteArray jAccKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(account_key));
  (*jenv)->SetByteArrayRegion (jenv, jAccKeyArr, 0, vsc_buffer_len(account_key), vsc_buffer_bytes(account_key));
  (*jenv)->SetObjectField(jenv, newObj, fidAccountKey, jAccKeyArr);
  
  // Free resources
  vsc_buffer_delete(enrollment_record);
  vsc_buffer_delete(account_key);
  
  return newObj;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_verifyPasswordRequestLen
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1verifyPasswordRequestLen
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {

  return 0;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_createVerifyPasswordRequest
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1createVerifyPasswordRequest
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpassword, jbyteArray jenrollmentRecord) {

  vsc_data_t password = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jpassword, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jpassword));

  vsc_data_t enrollment_record = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

  vsc_buffer_t *verify_password_request = vsc_buffer_new_with_capacity(vsce_phe_client_verify_password_request_len(c_ctx));

  vsce_error_t status = vsce_phe_client_create_verify_password_request(c_ctx, password, enrollment_record, verify_password_request);

  //TODO Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }

  jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(verify_password_request));
  (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(verify_password_request), vsc_buffer_bytes(verify_password_request));

  // Free resources
  vsc_buffer_delete(verify_password_request);
  
  return ret;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_checkResponseAndDecrypt
 * Signature: (J[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1checkResponseAndDecrypt
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jpassword, jbyteArray jenrollmentRecord, jbyteArray jverifyPasswordResponse) {

  vsc_data_t password = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jpassword, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jpassword));

  vsc_data_t enrollment_record = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

  vsc_data_t verify_password_response = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jverifyPasswordResponse, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jverifyPasswordResponse));

  vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

  vsce_error_t status = vsce_phe_client_check_response_and_decrypt(c_ctx, password, enrollment_record, verify_password_response, account_key);

  //TODO Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }
  
  jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(account_key));
  (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(account_key), vsc_buffer_bytes(account_key));

  // Free resources
  vsc_buffer_delete(account_key);
  
  return ret;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_rotateKeys
 * Signature: (J[B)Lvirgil/crypto/phe/PheClientRotateKeysResult;
 */
JNIEXPORT jobject JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1rotateKeys
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jupdateToken) {

  vsc_data_t update_token = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jupdateToken, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jupdateToken));

  vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
  vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

  vsce_error_t status = vsce_phe_client_rotate_keys(c_ctx, update_token, new_client_private_key, new_server_public_key);
  
  //TODO Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }

  // Create result class
  jclass cls = (*jenv)->FindClass(jenv, "virgil/crypto/phe/PheClientRotateKeysResult");
  if (NULL == cls) {
    printf("Class PheClientRotateKeysResult not found.\n");
    return NULL;
  }
  jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "()V");
  jobject newObj = (*jenv)->NewObject(jenv, cls, methodID);
  
  // Set new client private key
  jfieldID fidNewClientPrivateKey = (*jenv)->GetFieldID(jenv, cls, "newClientPrivateKey", "[B");
  jbyteArray jNewClientPrivateKeyArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_client_private_key));
  (*jenv)->SetByteArrayRegion (jenv, jNewClientPrivateKeyArr, 0, vsc_buffer_len(new_client_private_key), vsc_buffer_bytes(new_client_private_key));
  (*jenv)->SetObjectField(jenv, newObj, fidNewClientPrivateKey, jNewClientPrivateKeyArr);
  
  // Set new public key
  jfieldID fidNewPublicKey = (*jenv)->GetFieldID(jenv, cls, "newServerPublicKey", "[B");
  jbyteArray jNewPubArr = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_server_public_key));
  (*jenv)->SetByteArrayRegion (jenv, jNewPubArr, 0, vsc_buffer_len(new_server_public_key), vsc_buffer_bytes(new_server_public_key));
  (*jenv)->SetObjectField(jenv, newObj, fidNewPublicKey, jNewPubArr);

  // Free resources
  vsc_buffer_delete(new_client_private_key);
  vsc_buffer_delete(new_server_public_key);
  
  return newObj;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheClient_updateEnrollmentRecord
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheClient_1updateEnrollmentRecord
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jenrollmentRecord, jbyteArray jupdateToken) {

  vsc_data_t enrollment_record = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jenrollmentRecord, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jenrollmentRecord));

  vsc_data_t update_token = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jupdateToken, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jupdateToken));

  vsc_buffer_t *new_enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(c_ctx));

  vsce_error_t status = vsce_phe_client_update_enrollment_record(c_ctx, enrollment_record, update_token, new_enrollment_record);

  //TODO Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }
  
  jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(new_enrollment_record));
  (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(new_enrollment_record), vsc_buffer_bytes(new_enrollment_record));

  // Free resources
  vsc_buffer_delete(new_enrollment_record);

  return ret;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheCipher_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1new
  (JNIEnv *jenv, jobject jobj) {

  return vsce_phe_cipher_new();
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheCipher_close
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1close
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {

  vsce_phe_cipher_delete(c_ctx);
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheCipher_setupDefaults
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1setupDefaults
  (JNIEnv *jenv, jobject jobj, jlong c_ctx) {

  vsce_phe_cipher_setup_defaults(c_ctx);
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheCipher_encryptLen
  * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1encryptLen
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jplainTextLen) {

  return 0;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheCipher_decryptLen
  * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1decryptLen
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jint jcipherTextLen) {

  return 0;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheCipher_encrypt
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1encrypt
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jplainText, jbyteArray jaccountKey) {

  vsc_data_t plain_text = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jplainText, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jplainText));

  vsc_data_t account_key = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jaccountKey, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jaccountKey));

  vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_encrypt_len(c_ctx, plain_text.len));

  vsce_error_t status = vsce_phe_cipher_encrypt(c_ctx, plain_text, account_key, cipher_text);

  //TODO Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }
  
  jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(cipher_text));
  (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(cipher_text), vsc_buffer_bytes(cipher_text));

  // Free resources
  vsc_buffer_delete(cipher_text);

  return ret;
}

/*
 * Class:     virgil_crypto_phe_PheJNI
 * Method:    pheCipher_decrypt
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_virgil_crypto_phe_PheJNI_pheCipher_1decrypt
  (JNIEnv *jenv, jobject jobj, jlong c_ctx, jbyteArray jcipherText, jbyteArray jaccountKey) {

  vsc_data_t cipher_text = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jcipherText, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jcipherText));

  vsc_data_t account_key = vsc_data(
    (*jenv)->GetByteArrayElements(jenv, jaccountKey, JNI_FALSE),
    (*jenv)->GetArrayLength(jenv, jaccountKey));

  vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_decrypt_len(c_ctx, cipher_text.len));

  vsce_error_t status = vsce_phe_cipher_decrypt(c_ctx, cipher_text, account_key, plain_text);

  //TODO Handle error
  if(status != vsce_SUCCESS) {
    return NULL;
  }
  
  jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len(plain_text));
  (*jenv)->SetByteArrayRegion (jenv, ret, 0, vsc_buffer_len(plain_text), vsc_buffer_bytes(plain_text));

  // Free resources
  vsc_buffer_delete(plain_text);

  return ret;
}
