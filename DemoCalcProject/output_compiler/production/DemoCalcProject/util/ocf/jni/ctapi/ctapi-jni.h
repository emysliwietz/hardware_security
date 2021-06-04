/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class de_cardcontact_ctapi_CTAPI */

#ifndef _Included_de_cardcontact_ctapi_CTAPI
#define _Included_de_cardcontact_ctapi_CTAPI
#ifdef __cplusplus
extern "C" {
#endif
#undef de_cardcontact_ctapi_CTAPI_OK
#define de_cardcontact_ctapi_CTAPI_OK 0L
#undef de_cardcontact_ctapi_CTAPI_ERR_INVALID
#define de_cardcontact_ctapi_CTAPI_ERR_INVALID -1L
#undef de_cardcontact_ctapi_CTAPI_ERR_CT
#define de_cardcontact_ctapi_CTAPI_ERR_CT -8L
#undef de_cardcontact_ctapi_CTAPI_ERR_TRANS
#define de_cardcontact_ctapi_CTAPI_ERR_TRANS -10L
#undef de_cardcontact_ctapi_CTAPI_ERR_MEMORY
#define de_cardcontact_ctapi_CTAPI_ERR_MEMORY -11L
#undef de_cardcontact_ctapi_CTAPI_ERR_HOST
#define de_cardcontact_ctapi_CTAPI_ERR_HOST -127L
#undef de_cardcontact_ctapi_CTAPI_ICC1
#define de_cardcontact_ctapi_CTAPI_ICC1 0L
#undef de_cardcontact_ctapi_CTAPI_CT
#define de_cardcontact_ctapi_CTAPI_CT 1L
#undef de_cardcontact_ctapi_CTAPI_HOST
#define de_cardcontact_ctapi_CTAPI_HOST 2L
#undef de_cardcontact_ctapi_CTAPI_ICC2
#define de_cardcontact_ctapi_CTAPI_ICC2 2L
#undef de_cardcontact_ctapi_CTAPI_REMOTE_HOST
#define de_cardcontact_ctapi_CTAPI_REMOTE_HOST 5L
#undef de_cardcontact_ctapi_CTAPI_NO_READER_NAME
#define de_cardcontact_ctapi_CTAPI_NO_READER_NAME 1L
/*
 * Class:     de_cardcontact_ctapi_CTAPI
 * Method:    CT_Init
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_de_cardcontact_ctapi_CTAPI_CT_1Init
  (JNIEnv *, jobject, jint, jint);

/*
 * Class:     de_cardcontact_ctapi_CTAPI
 * Method:    CT_Close
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_de_cardcontact_ctapi_CTAPI_CT_1Close
  (JNIEnv *, jobject, jint);

/*
 * Class:     de_cardcontact_ctapi_CTAPI
 * Method:    CT_Data
 * Signature: (IBB[BI[B)I
 */
JNIEXPORT jint JNICALL Java_de_cardcontact_ctapi_CTAPI_CT_1Data
  (JNIEnv *, jobject, jint, jbyte, jbyte, jbyteArray, jint, jbyteArray);

/*
 * Class:     de_cardcontact_ctapi_CTAPI
 * Method:    CT_List_native
 * Signature: ([BI)I
 */
JNIEXPORT jint JNICALL Java_de_cardcontact_ctapi_CTAPI_CT_1List_1native
  (JNIEnv *, jobject, jbyteArray, jint);

/*
 * Class:     de_cardcontact_ctapi_CTAPI
 * Method:    setCTAPILib
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_de_cardcontact_ctapi_CTAPI_setCTAPILib
  (JNIEnv *, jobject, jstring);

#ifdef __cplusplus
}
#endif
#endif
