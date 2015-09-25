#include "senderkeyrecord.h"

#include "../../state/LocalStorageProtocol.pb.h"

#include "../../invalidkeyidexception.h"

SenderKeyRecord::SenderKeyRecord()
{

}

SenderKeyRecord::SenderKeyRecord(const QByteArray &serialized)
{
    textsecure::SenderKeyRecordStructure senderKeyRecordStructure;
    senderKeyRecordStructure.ParseFromArray(serialized.constData(), serialized.size());

    for (int i = 0; i < senderKeyRecordStructure.senderkeystates_size(); i++) {
        textsecure::SenderKeyStateStructure structure = senderKeyRecordStructure.senderkeystates(i);
        senderKeyStates.append(new SenderKeyState(structure));
    }
}

SenderKeyState *SenderKeyRecord::getSenderKeyState()
{
    if (!senderKeyStates.isEmpty()) {
        return senderKeyStates.first();
    }

    throw InvalidKeyIdException(QString("No key state in record!"));
}

SenderKeyState *SenderKeyRecord::getSenderKeyState(int keyId)
{
    foreach (SenderKeyState *state, senderKeyStates) {
        if (state->getKeyId() == keyId) {
            return state;
        }
    }

    throw InvalidKeyIdException(QString("No keys for: %1").arg(keyId));
}

void SenderKeyRecord::addSenderKeyState(int id, int iteration, const QByteArray &chainKey, const DjbECPublicKey &signatureKey)
{
    senderKeyStates.prepend(new SenderKeyState(id, iteration, chainKey, signatureKey));

    if (senderKeyStates.size() > SenderKeyRecord::MAX_STATES) {
        senderKeyStates.removeLast();
    }
}

void SenderKeyRecord::setSenderKeyState(int id, int iteration, const QByteArray &chainKey, const ECKeyPair &signatureKey)
{
    senderKeyStates.clear();
    senderKeyStates.append(new SenderKeyState(id, iteration, chainKey, signatureKey));
}

QByteArray SenderKeyRecord::serialize() const
{
    textsecure::SenderKeyRecordStructure recordStructure;

    foreach (SenderKeyState *senderKeyState, senderKeyStates) {
        recordStructure.add_senderkeystates()->CopyFrom(senderKeyState->getStructure());
    }

    ::std::string recordStructureString = recordStructure.SerializeAsString();
    QByteArray recordStructureBytes(recordStructureString.data(), recordStructureString.length());

    return recordStructureBytes;
}

bool SenderKeyRecord::isEmpty() const
{
    return senderKeyStates.isEmpty();
}
