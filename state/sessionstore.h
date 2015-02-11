#ifndef SESSIONSTORE_H
#define SESSIONSTORE_H

#include "sessionrecord.h"

class SessionStore
{
public:
    virtual SessionRecord *loadSession(qulonglong recipientId, int deviceId) = 0;
    virtual QList<int> getSubDeviceSessions(qulonglong recipientId) = 0;
    virtual void storeSession(qulonglong recipientId, int deviceId, SessionRecord *record) = 0;
    virtual bool containsSession(qulonglong recipientId, int deviceId) = 0;
    virtual void deleteSession(qulonglong recipientId, int deviceId) = 0;
    virtual void deleteAllSessions(qulonglong recipientId) = 0;
};

#endif // SESSIONSTORE_H
