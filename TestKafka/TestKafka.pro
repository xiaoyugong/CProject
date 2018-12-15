TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

HEADERS += packet.pb-c.h

SOURCES += main.c \
packet.pb-c.c \
rdkafka_consumer_example.c

LIBS += /usr/local/lib/librdkafka.a \
/usr/lib/x86_64-linux-gnu/libpthread.so \
/usr/lib/x86_64-linux-gnu/libpcap.so \
/usr/lib/x86_64-linux-gnu/libssl.so \
/usr/lib/x86_64-linux-gnu/libcrypto.so \
/usr/lib/x86_64-linux-gnu/libz.so \
/usr/lib/x86_64-linux-gnu/libdl.so \
/usr/lib/x86_64-linux-gnu/librt.so \
/usr/local/lib/libprotobuf-c.a
