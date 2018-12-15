TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c

LIBS += ~/nDPI/src/lib/.libs/libndpi.a \
/usr/lib/x86_64-linux-gnu/libpthread.so \
/usr/lib/x86_64-linux-gnu/libpcap.so

DISTFILES += \
    filter.bpf

