LOCAL_PATH := $(call my-dir)  


include $(CLEAR_VARS)

LOCAL_CXXFLAGS +=  -g -O0
LOCAL_ARM_MODE := arm
LOCAL_MODULE    := IHook64
LOCAL_STATIC_LIBRARIES:= InlineHook
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../hook
LOCAL_SRC_FILES := InlineHook.cpp
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

include $(BUILD_SHARED_LIBRARY)