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
        SenderKeyState *state = new SenderKeyState(structure);
        senderKeyStates.append(state);
    }
}

SenderKeyState *SenderKeyRecord::getSenderKeyState(int keyId)
{
    if (!senderKeyStates.isEmpty() && (keyId < senderKeyStates.size())) {
        return senderKeyStates.at(keyId);
    } else {
        throw InvalidKeyIdException(QString("No key state %1 in record!").arg(keyId));
    }
}

void SenderKeyRecord::addSenderKeyState(int id, int iteration, const QByteArray &chainKey, const DjbECPublicKey &signatureKey)
{
    senderKeyStates.append(new SenderKeyState(id, iteration, chainKey, signatureKey));
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
