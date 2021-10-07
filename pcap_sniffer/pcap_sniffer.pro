TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -L$$PWD/libpcap/lib
LIBS += -lpcap

INCLUDEPATH += libpcap/include

SOURCES += \
    sniffer_udp.c
