#include "sessionrecord.h"

const int SessionRecord::ARCHIVED_STATES_MAX_LENGTH = 50;

SessionRecord::SessionRecord()
{
    fresh = true;
    this->sessionState = new SessionState();
}

SessionRecord::SessionRecord(SessionState *sessionState)
{
    this->sessionState = sessionState;
    fresh = false;
}

SessionRecord::SessionRecord(const QByteArray &serialized)
{
    textsecure::RecordStructure record;
    record.ParsePartialFromArray(serialized.constData(), serialized.size());
    sessionState = new SessionState(record.currentsession());
    fresh = false;

    for (int i = 0; i < record.previoussessions_size(); i++) {
        previousStates.append(new SessionState(record.previoussessions(i)));
    }
}

bool SessionRecord::hasSessionState(int version, const QByteArray &aliceBaseKey)
{
    if (sessionState->getSessionVersion() == version
            && aliceBaseKey == sessionState->getAliceBaseKey())
    {
        return true;
    }

    foreach (SessionState *state, previousStates) {
        if (state->getSessionVersion() == version
                && aliceBaseKey == state->getAliceBaseKey())
        {
            return true;
        }
    }

    return false;
}

SessionState *SessionRecord::getSessionState()
{
    return sessionState;
}

QList<SessionState *> SessionRecord::getPreviousSessionStates()
{
    return previousStates;
}

bool SessionRecord::isFresh() const
{
    return fresh;
}

void SessionRecord::promoteState(SessionState *promotedState)
{
    previousStates.insert(0, promotedState);
    sessionState = promotedState;
    if (previousStates.size() > ARCHIVED_STATES_MAX_LENGTH) {
        previousStates.removeLast();
    }
}

void SessionRecord::archiveCurrentState()
{
    promoteState(new SessionState());
}

void SessionRecord::setState(SessionState *sessionState)
{
    this->sessionState = sessionState;
}

QByteArray SessionRecord::serialize() const
{
    textsecure::RecordStructure record;
    record.mutable_currentsession()->CopyFrom(sessionState->getStructure());

    foreach (SessionState *previousState, previousStates) {
        record.add_previoussessions()->CopyFrom(previousState->getStructure());
    }

    ::std::string serialized = record.SerializeAsString();
    return QByteArray(serialized.data(), serialized.length());
}
