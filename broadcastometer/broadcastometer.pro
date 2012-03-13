TEMPLATE = app
TARGET = broadcastometer

QT += network

LIBS    += -Wl,-rpath,lib/qpcap/qpcap -Llib/qpcap/qpcap -lqpcap
INCLUDEPATH += lib/qpcap/qpcap

SOURCES += packetstats.cpp main.cpp
HEADERS += packetstats.h
