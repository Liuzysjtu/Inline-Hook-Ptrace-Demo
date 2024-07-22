#include <jni.h>
#include <string>

static unsigned int uiTimeCounter = 0x1;

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_ibored_MainActivity_UpdateResult(JNIEnv *env, jclass clazz) {
    unsigned  int uiLocalVar = 1;

    uiTimeCounter += uiLocalVar;

    if(uiTimeCounter > 300000)
    {
        //win
        return env->NewStringUTF("Enough. You Win!");
    }
    else
    {
        //wait
        return env->NewStringUTF("Just Wait.");
    }
}