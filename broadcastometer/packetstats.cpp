#include <QString>
#include <QStringList>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QVector>
#include <QtAlgorithms>
#include <QHashIterator>
#include <netinet/ether.h>

#include "qpcapethernetpacket.h"
#include "qpcapippacket.h"
#include "qpcaptcppacket.h"
#include "qpcapudppacket.h"

#include "packetstats.h"

#define INTERVAL 3000


void BytePacketCount::inc(long bytes)
{
    this->packets++;
    this->bytes += bytes;
}

QString BytePacketCount::toJson() const
{
    long bytes_per_sec = bytes / 3;
    return "\"packet_count\": " + QString::number(packets) + ", \"bytes_per_sec\": " + QString::number(bytes_per_sec);
}

void TypeCount::inc(long bytes, QString type)
{
    BytePacketCount count = counter[type];
    count.inc(bytes);
    counter[type] = count;
}

QString TypeCount::toJson() const
{
    QStringList stringlist;
    QHashIterator<QString, BytePacketCount> i(counter);
    while ( i.hasNext() ) {
        i.next();
	stringlist << ("\"" + i.key() + "\": {" + i.value().toJson() + "}");
    }
    return "{" + stringlist.join(", ") + "}";
}

void MacStat::inc(long bytes)
{
    counter.inc(bytes);
}

void MacStat::inc(long bytes, QString type)
{
    inc(bytes);
    type_counter.inc(bytes, type);
}

bool operator<(const MacStat& lhs, const MacStat &rhs)
{
    return lhs.getCounter().getPacketCount() < rhs.getCounter().getPacketCount();
}

PacketStats::PacketStats( QObject *parent )
    : QObject(parent), interval(3000)
{
}

PacketStats::~PacketStats()
{
}

void analizePacket(const uchar * packet, QString& type, QString& src_mac, QString& dest_mac) {
    QPcapEthernetPacket ether(packet);
    src_mac = ether.sourceHost();
    dest_mac = ether.destHost();

    if (ether.frameType() == ETHERTYPE_ARP) {
        type = "ARP";
	return;
    }

    if (ether.isIpPacket()) {
        QPcapIpPacket ip = ether.toIpPacket();
	switch(ip.protocol()) {
	case QPcapIpPacket::IcmpProtocol:
	    type = "ICMP";
	    return;
	case QPcapIpPacket::IgmpProtocol:
	    type = "IGMP";
	    return;
	case QPcapIpPacket::Icmp6Protocol:
	    type = "ICMPv6";
	    return;
	case QPcapIpPacket::Ip6Protocol:
	    type = "IPv6";
	    // break down multicast groups?
	    return;
	case QPcapIpPacket::UdpProtocol:
	    QPcapUdpPacket udp = ip.toUdpPacket();
	    switch ( udp.destPort() ) {
	    case 67:
	    case 68:
	        type = "DHCP";
		return;
	    case 137:
	        type = "NetBIOS";
		return;
	    case 1900:
	        type = "UPnP";
		return;
	    case 5353:
	        type = "mDNS";
		return;
	    case 17500:
	        type = "Dropbox";
		return;
	    }
	    type = "UDP-" + QString::number(udp.destPort());
	    return;
	}
    }
    type = "other";
}

void PacketStats::process( QPcapHeader header, const uchar *packet )
{
    QString type, src_mac, dest_mac;
    analizePacket(packet, type, src_mac, dest_mac);

    MacStat& src_stat = src_counter[src_mac];
    src_stat.inc(header.packetLength(), type);
    src_counter[src_mac] = src_stat;

    MacStat& dest_stat = dest_counter[dest_mac];
    dest_stat.inc(header.packetLength(), type);
    dest_counter[dest_mac] = dest_stat;

    counter.inc(header.packetLength());
    type_counter.inc(header.packetLength(), type);

    last_timestamp = header.timeStamp();
}

void hashToSortedList(QHash<QString, MacStat> &hash, QVector<QPair<MacStat, QString> > &list) {
    list.reserve(hash.size());
    QHashIterator<QString, MacStat> i(hash);
    while ( i.hasNext() ) {
        i.next();
	list.append(QPair<MacStat, QString>(i.value(), i.key()));
    }
    qSort(list.begin(), list.end(), qGreater<QPair<MacStat, QString> >());
}

QString macs_to_string(QVector<QPair<MacStat, QString> > &macs) {
    QStringList mac_strings;
    int i = 0;
    while (i < 3 && i < macs.size()) {
        mac_strings << ("{\"mac\": \"" + macs[i].second + "\", " + macs[i].first.getCounter().toJson() + "}");
	i++;
    }
    return mac_strings.join(", ");
}

void PacketStats::flushToFile()
{
    qDebug() << "flush to file";

    QVector<QPair<MacStat, QString> > src_macs;
    hashToSortedList(src_counter, src_macs);

    QVector<QPair<MacStat, QString> > dest_macs;
    hashToSortedList(dest_counter, dest_macs);

    QFile file(filename);
    file.open(QIODevice::WriteOnly | QIODevice::Text);
    QTextStream out(&file);
    out << "{\n";
    out << "  " << counter.toJson() << ",\n";
    out << "  \"types\":" << type_counter.toJson() << ",\n";
    out << "  \"src_macs\": [" << macs_to_string(src_macs) << "],\n";
    out << "  \"dest_macs\": [" << macs_to_string(dest_macs) << "],\n";
    out << "  \"timestamp\":" << last_timestamp.tv_sec << "\n";
    out << "}\n";
    file.close();
    flush();
}

void PacketStats::flush()
{
    counter = BytePacketCount();
    type_counter = TypeCount();
    src_counter = QHash<QString, MacStat>();
    dest_counter = QHash<QString, MacStat>();
}
