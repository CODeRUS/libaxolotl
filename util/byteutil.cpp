#include "byteutil.h"

ByteUtil::ByteUtil()
{
}

QByteArray ByteUtil::combine(const QList<QByteArray> &items)
{
    QByteArray result;
    foreach (const QByteArray &item, items) {
        result.append(item);
    }
    return result;
}

QList<QByteArray> ByteUtil::split(const QByteArray &input, int firstLength, int secondLength, int thirdLength)
{
    QList<QByteArray> result;
    result.append(input.mid(0, firstLength));
    result.append(input.mid(firstLength, secondLength));
    if (thirdLength > -1) {
        result.append(input.mid(firstLength + secondLength, thirdLength));
    }
    return result;
}

QByteArray ByteUtil::trim(const QByteArray &input, int length)
{
    return input.mid(0, length);
}

qint8 ByteUtil::intsToByteHighAndLow(int highValue, int lowValue)
{
    return (highValue << 4 | lowValue) & 0xFF;
}

int ByteUtil::highBitsToInt(qint8 input)
{
    return (input & 0xFF) >> 4;
}

int ByteUtil::lowBitsToInt(qint8 input)
{
    return input & 0xF;
}

int ByteUtil::intToByteArray(QByteArray &input, int offset, int value)
{
    input[offset + 3] = (char)(value % 256);
    input[offset + 2] = (char)((value >> 8) % 256);
    input[offset + 1] = (char)((value >> 16) % 256);
    input[offset]     = (char)((value >> 24) % 256);
    return 4;
}
