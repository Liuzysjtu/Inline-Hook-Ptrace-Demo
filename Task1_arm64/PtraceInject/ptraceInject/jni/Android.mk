LOCAL_PATH := $(call my-dir)  
  
include $(CLEAR_VARS)  
LOCAL_MODULE := inject64
LOCAL_SRC_FILES := ptraceInject.c InjectModule.c 
  
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog  
  
include $(BUILD_EXECUTABLE)  