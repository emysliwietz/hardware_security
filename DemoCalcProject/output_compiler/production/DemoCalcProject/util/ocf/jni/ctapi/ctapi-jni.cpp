/*
 *  ---------
 * |.**> <**.|  CardContact
 * |*       *|  Software & System Consulting
 * |*       *|  Minden, Germany
 * |'**> <**'|  Copyright (c) 2000-2014. All rights reserved
 *  ---------
 *
 * See file LICENSE for details on licensing
 *
 * Abstract :       Implementation of a CTAPI Interface for Java.
 *
 * Author :         Frank Thater (FTH), Andreas Schwier (ASC)
 *
 * Last modified:   10/04/2014
 *
 *****************************************************************************/

#ifdef DEBUG
#include <stdio.h>
#endif

#include <jni.h>
#include "ctapi-jni.h"
#include "ctapi.h"

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <malloc.h>
#include <string.h>


#ifdef WIN32
#define LINKAGE __stdcall
#else
#define LINKAGE
#endif


typedef signed char (LINKAGE *CT_LIST_t) (
	unsigned char *readers,		/* Port / Reader list buffer */
	unsigned short *lr,		/* Length of buffer */
	unsigned short options		/* Processing options */
);

typedef signed char (LINKAGE *CT_INIT_t) (
	unsigned short Ctn,		/* Terminal Number */
	unsigned short pn		/* Port Number */
);

typedef signed char (LINKAGE *CT_CLOSE_t) (
	unsigned short Ctn		/* Terminal Number */
);

typedef signed char (LINKAGE *CT_DATA_t) (
	unsigned short ctn,		/* Terminal Number */
	unsigned char  *dad,		/* Destination */
	unsigned char  *sad,		/* Source */
	unsigned short lc,		/* Length of command */
	unsigned char  *cmd,		/* Command/Data Buffer */
	unsigned short *lr,		/* Length of Response */
	unsigned char  *rsp		/* Response */
);



/**
 * setReader(String name);
 *
 * Set shared object / DLL file name for reader
 *
 * Class:     de_cardcontact_ctapi_CTAPI
 * Method:    setCTAPILib
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_de_cardcontact_ctapi_CTAPI_setCTAPILib (JNIEnv *env, jobject obj, jstring libname)
{
#ifdef WIN32
	HMODULE mod;
	HINSTANCE handle;
#else
	void *handle;
	char *error;
#endif

	const char* msg=env->GetStringUTFChars(libname,0);

#ifdef DEBUG
	printf("Using Libname %s\n", msg);
#endif

	// Get the class of the object
	jclass cls = env->GetObjectClass(obj);
	jfieldID fieldID;

	CT_INIT_t CT_INIT;
	CT_CLOSE_t CT_CLOSE;
	CT_DATA_t CT_DATA;
	CT_LIST_t CT_LIST;

#ifdef WIN32
	/* for support of WIN32 DLLs */

	if((handle = LoadLibraryA(msg)) == NULL) {

		jclass newExcpClass = env->FindClass("java/lang/UnsatisfiedLinkError");

		if (newExcpClass == 0) { /* Unable to find the new exception class, give up. */
			return;
		}
		env->ThrowNew(newExcpClass, "Unable to find DLL containing CTAPI information");
	}

	mod = GetModuleHandleA(msg);

	CT_INIT = (CT_INIT_t) GetProcAddress(mod, "CT_init");
	if(CT_INIT == NULL) {

		jclass newExcpClass = env->FindClass("java/lang/UnsatisfiedLinkError");

		if (newExcpClass == 0) { /* Unable to find the new exception class, give up. */
			return;
		}
		env->ThrowNew(newExcpClass, "Unable to find CT_init reference");

	}

	CT_CLOSE = (CT_CLOSE_t) GetProcAddress(mod, "CT_close");
	if(CT_CLOSE== NULL) {

		jclass newExcpClass = env->FindClass("java/lang/UnsatisfiedLinkError");

		if (newExcpClass == 0) { /* Unable to find the new exception class, give up. */
			return;
		}
		env->ThrowNew(newExcpClass, "Unable to find CT_close reference");
	}

	CT_DATA = (CT_DATA_t) GetProcAddress(mod, "CT_data");
	if(CT_DATA == NULL) {

		jclass newExcpClass = env->FindClass("java/lang/UnsatisfiedLinkError");

		if (newExcpClass == 0) { /* Unable to find the new exception class, give up. */
			return;
		}
		env->ThrowNew(newExcpClass, "Unable to find CT_data reference");

	}

	CT_LIST = (CT_LIST_t) GetProcAddress(mod, "CT_list");

#else
	/* assume running under the Linux OS */

	if((handle = dlopen(msg, RTLD_NOW | RTLD_GLOBAL)) == NULL) {

		jclass newExcpClass = env->FindClass("java/lang/UnsatisfiedLinkError");

		if (newExcpClass == 0) { /* Unable to find the new exception class, give up. */
			return;
		}
		env->ThrowNew(newExcpClass, dlerror());

	}

	CT_INIT = (CT_INIT_t) dlsym(handle, "CT_init");
	if((error = dlerror()) != NULL) {

		jclass newExcpClass = env->FindClass("java/lang/UnsatisfiedLinkError");

		if (newExcpClass == 0) { /* Unable to find the new exception class, give up. */
			return;
		}
		env->ThrowNew(newExcpClass, error);

	}

	CT_CLOSE = (CT_CLOSE_t) dlsym(handle, "CT_close");
	if((error = dlerror()) != NULL) {

		jclass newExcpClass = env->FindClass("java/lang/UnsatisfiedLinkError");

		if (newExcpClass == 0) { /* Unable to find the new exception class, give up. */
			return;
		}
		env->ThrowNew(newExcpClass, error);

	}

	CT_DATA = (CT_DATA_t) dlsym(handle, "CT_data");
	if((error = dlerror()) != NULL) {

		jclass newExcpClass = env->FindClass("java/lang/UnsatisfiedLinkError");

		if (newExcpClass == 0) { /* Unable to find the new exception class, give up. */
			return;
		}
		env->ThrowNew(newExcpClass, error);

	}

	CT_LIST = (CT_LIST_t) dlsym(handle, "CT_list");
	if((error = dlerror()) != NULL) {
		CT_LIST = NULL;
	}
#endif

	fieldID = env->GetFieldID(cls, "ctInitPointer", "J");
	env->SetLongField(obj, fieldID, (jlong) CT_INIT);

	fieldID = env->GetFieldID(cls, "ctClosePointer", "J");
	env->SetLongField(obj, fieldID, (jlong) CT_CLOSE);

	fieldID = env->GetFieldID(cls, "ctDataPointer", "J");
	env->SetLongField(obj, fieldID, (jlong) CT_DATA);

	fieldID = env->GetFieldID(cls, "ctListPointer", "J");
	env->SetLongField(obj, fieldID, (jlong) CT_LIST);

	env->ReleaseStringUTFChars(libname, msg);
}



/*
 * Class:     de_cardcontact_ctapi_CTAPI
 * Method:    CT_Init
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_de_cardcontact_ctapi_CTAPI_CT_1Init (JNIEnv * env, jobject obj, jint ctn, jint pn)
{
	int rc;

	// Get the class of the object
	jclass cls = env->GetObjectClass(obj);
	jfieldID fieldID;
	CT_INIT_t pCtInit;

	fieldID = env->GetFieldID(cls, "ctInitPointer", "J");

	pCtInit = (CT_INIT_t) env->GetLongField(obj, fieldID);

#ifdef DEBUG
	printf("Java CT_init(%d, %d)\n", ctn, pn);
	printf("Pointer CT_init = %p\n", pCtInit);
#endif

	rc = (*pCtInit)((unsigned short)ctn, (unsigned short)pn);

	return rc;

}



/*
 * Class:     de_cardcontact_ctapi_CTAPI
 * Method:    CT_Close
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_de_cardcontact_ctapi_CTAPI_CT_1Close (JNIEnv *env, jobject obj, jint ctn)
{
	int rc;

	// Get the class of the object
	jclass cls = env->GetObjectClass(obj);
	jfieldID fieldID;
	CT_CLOSE_t pCtClose;

	fieldID = env->GetFieldID(cls, "ctClosePointer", "J");

	pCtClose = (CT_CLOSE_t) env->GetLongField(obj, fieldID);

#ifdef DEBUG
	printf("Java CT_close(%d)\n", ctn);
	printf("Pointer CT_close = %p\n", pCtClose);
#endif

	rc = (*pCtClose)((unsigned short)ctn);

	return rc;

}



/*
 * Class:     de_cardcontact_ctapi_CTAPI
 * Method:    CT_Data
 * Signature: (IBB[BI[B)I
 */
JNIEXPORT jint JNICALL Java_de_cardcontact_ctapi_CTAPI_CT_1Data (JNIEnv *env, jobject obj, jint ctn, jbyte dad, jbyte sad, jbyteArray jcmd, jint lr, jbyteArray jrsp)
{
	int rc;

	// Get the class of the object
	jclass cls = env->GetObjectClass(obj);
	jfieldID fieldID;
	CT_DATA_t pCtData;

	fieldID = env->GetFieldID(cls, "ctDataPointer", "J");

	pCtData = (CT_DATA_t) env->GetLongField(obj, fieldID);

#ifdef DEBUG
	printf("Java CT_data()\n");
	printf("Pointer CT_data = %p\n", pCtData);
#endif

	jbyte *cmd=env->GetByteArrayElements(jcmd, 0);
	jbyte *rsp=env->GetByteArrayElements(jrsp, 0);

	unsigned char lsad = (unsigned char) sad;
	unsigned char ldad = (unsigned char) dad;

	unsigned short int lenr = lr;
	unsigned short lc = env->GetArrayLength(jcmd);

	rc = (*pCtData)((unsigned short)ctn, (unsigned char *)&ldad, (unsigned char *)&lsad, lc, (unsigned char *)cmd, &lenr, (unsigned char*)rsp);

	env->ReleaseByteArrayElements(jcmd, cmd, 0);
	env->ReleaseByteArrayElements(jrsp, rsp, 0);

	if(rc < 0) {
		return rc;
	}
	return lenr;
}



/*
 * Class:     de_cardcontact_ctapi_CTAPI
 * Method:    CT_List_native
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_de_cardcontact_ctapi_CTAPI_CT_1List_1native (JNIEnv *env, jobject obj, jbyteArray jreaders, jint options)
{
	int rc;

	// Get the class of the object
	jclass cls = env->GetObjectClass(obj);
	jfieldID fieldID;
	CT_LIST_t pCtList;

	fieldID = env->GetFieldID(cls, "ctListPointer", "J");

	pCtList = (CT_LIST_t) env->GetLongField(obj, fieldID);

	if (pCtList == NULL) {
#ifdef DEBUG
		printf("CT_list not supported\n");
#endif
		return -1;
	}

	jbyte *readers=env->GetByteArrayElements(jreaders,0);
	unsigned short lr = env->GetArrayLength(jreaders);

	rc = (*pCtList)((unsigned char *)readers, &lr, (unsigned short)options);

	env->ReleaseByteArrayElements(jreaders, readers, 0);

	if(rc < 0) {
		return rc;
	}
	return lr;
}
