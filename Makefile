ARCHS = arm64

TARGET := iphone:clang:latest:16.5
INSTALL_TARGET_PROCESSES = ReportCrash

THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = crashreportdetails

crashreportdetails_FILES = Tweak.x
crashreportdetails_CFLAGS = -fobjc-arc -I./dependencies/include
crashreportdetails_LDFLAGS = -L./dependencies/lib -lcapstone

include $(THEOS_MAKE_PATH)/tweak.mk
