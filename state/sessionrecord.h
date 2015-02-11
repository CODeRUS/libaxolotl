#ifndef SESSIONRECORD_H
#define SESSIONRECORD_H

#include "sessionstate.h"

#include <QList>
#include <QByteArray>

class SessionRecord
{
public:
    SessionRecord();
    SessionRecord(SessionState *sessionState);
    SessionRecord(const QByteArray &serialized);

    bool hasSessionState(int version, const QByteArray &aliceBaseKey);
    SessionState *getSessionState();
    QList<SessionState*> getPreviousSessionStates();
    bool isFresh() const;
    void promoteState(SessionState *promotedState);
    void archiveCurrentState();
    void setState(SessionState *sessionState);
    QByteArray serialize() const;

private:
    static const int ARCHIVED_STATES_MAX_LENGTH;
    SessionState *sessionState;
    QList<SessionState*> previousStates;
    bool fresh;
};

#endif // SESSIONRECORD_H
