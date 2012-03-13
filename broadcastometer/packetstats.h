// -*- c++ -*-

#ifndef PACKET_STATS_H
#define PACKET_STATS_H

#include <QObject>
#include <QHash>

#include <qpcap.h>

class BytePacketCount
{
public:
    BytePacketCount() : packets(0), bytes(0) { };
    ~BytePacketCount() { };
    void inc(long bytes);
    int getPacketCount() const { return packets; }
    long getByteCount() const { return bytes; }
    QString toJson() const;
private:
    int packets;
    long bytes;
};

class TypeCount
{
public:
    TypeCount() { };
    ~TypeCount() { };
    void inc(long bytes, QString type);
    QString toJson() const;
private:
    QHash<QString, BytePacketCount> counter;
};

class MacStat
{
public:
    MacStat() { };
    ~MacStat() { };
    void inc(long bytes);
    void inc(long bytes, QString type);
    const BytePacketCount& getCounter() const { return counter; }
private:
    BytePacketCount counter;
    TypeCount type_counter;
};
bool operator<(const MacStat &lhs, const MacStat &rhs);

class PacketStats : public QObject
{
    Q_OBJECT
public:
    PacketStats( QObject *parent=0 );
    ~PacketStats();
    void setFilename(QString& filename) { this->filename = filename; }
    void flush();

public slots:
    void process( QPcapHeader header, const uchar *packet );
    void flushToFile();

private:
    BytePacketCount counter;
    QHash<QString, MacStat> src_counter;
    QHash<QString, MacStat> dest_counter;
    TypeCount type_counter;
    QString filename;
    int interval;
    timeval last_timestamp;
};

#endif // PACKET_STATS_H
