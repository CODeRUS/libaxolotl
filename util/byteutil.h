#ifndef BYTEUTIL_H
#define BYTEUTIL_H

#include <QByteArray>
#include <QList>

class ByteUtil
{
public:
    ByteUtil();

    static QByteArray combine(const QList<QByteArray> &items);
    static QList<QByteArray> split(const QByteArray &input, int firstLength, int secondLength, int thirdLength = -1);
    static QByteArray trim(const QByteArray &input, int length);
    static qint8 intsToByteHighAndLow(int highValue, int lowValue);
    static int highBitsToInt(qint8 input);
    static int lowBitsToInt(qint8 input);
    static int intToByteArray(QByteArray &input, int offset, int value);
};

#endif // BYTEUTIL_H
