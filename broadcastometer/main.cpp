#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>
#include <QString>
#include <QStringList>
#include <QTimer>

#include "qpcap.h"

#include "packetstats.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    QStringList arguments = QCoreApplication::arguments();

    if (arguments.count() != 3) {
        qDebug() << "Not enough parameters!";
        qDebug() << "Usage:";
        qDebug() << "    broadcastometer networkinterface jsonfile";
	return 1;
    }
    QString networkinterface = arguments[1];
    QString jsonfilename = arguments[2];

    QPcap pcap;

    bool ok;
    ok = pcap.open( networkinterface, 40, true );
    if (!ok) {
        qDebug() << "Unable to open, " << pcap.errorString();
        return 1;
    }

    ok = pcap.setFilter( QString("ether broadcast or ether multicast") );
    if (!ok) {
        qDebug() << "filter failed, " << pcap.errorString();
        return 1;
    }

    PacketStats stats;
    stats.setFilename(jsonfilename);
    stats.connect( &pcap, SIGNAL(packetReady(QPcapHeader, const uchar *)), SLOT(process(QPcapHeader, const uchar *)) );

    QTimer timer(&stats);
    stats.connect(&timer, SIGNAL(timeout()), &stats, SLOT(flushToFile()));
    timer.start(3000);

    pcap.start();

    app.exec();

    pcap.close();
}
