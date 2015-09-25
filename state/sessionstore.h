#ifndef SESSIONSTORE_H
#define SESSIONSTORE_H

#include "sessionrecord.h"

#include "../axolotladdress.h"

class SessionStore
{
public:
    virtual SessionRecord *loadSession(const AxolotlAddress &remoteAddress) = 0;
    virtual QList<int> getSubDeviceSessions(const QString &name) = 0;
    virtual void storeSession(const AxolotlAddress &remoteAddress, SessionRecord *record) = 0;
    virtual bool containsSession(const AxolotlAddress &remoteAddressd) = 0;
    virtual void deleteSession(const AxolotlAddress &remoteAddress) = 0;
    virtual void deleteAllSessions(const QString &name) = 0;
};

#endif // SESSIONSTORE_H
