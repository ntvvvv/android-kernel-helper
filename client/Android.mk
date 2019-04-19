
LOCAL_PATH := $(my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := rkc
LOCAL_SRC_FILES := src/main.c
                    
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CFLAGS     := -Wall -Wextra -fvisibility=hidden -Wunused-parameter
LOCAL_CONLYFLAGS := -std=c11
LOCAL_LDLIBS     := -llog

include $(BUILD_EXECUTABLE)
