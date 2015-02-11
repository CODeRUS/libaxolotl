#include "senderkeystate.h"
#include "../../ecc/curve.h"

SenderKeyState::SenderKeyState()
{

}

SenderKeyState::SenderKeyState(int id, int iteration, const QByteArray &chainKey, const DjbECPublicKey &signatureKey)
{
    senderKeyStateStructure = textsecure::SenderKeyStateStructure();
    senderKeyStateStructure.set_senderkeyid(id);
    senderKeyStateStructure.mutable_senderchainkey()->set_iteration(iteration);
    senderKeyStateStructure.mutable_senderchainkey()->set_seed(chainKey.constData(),
                                                               chainKey.size());
    senderKeyStateStructure.mutable_sendersigningkey()->set_public_(signatureKey.serialize().constData(),
                                                                    signatureKey.serialize().size());

    /*textsecure::SenderKeyStateStructure::SenderChainKey senderChainKeyStructure;
    senderChainKeyStructure.set_iteration(iteration);
    senderChainKeyStructure.set_seed(chainKey.constData());

    textsecure::SenderKeyStateStructure::SenderSigningKey signingKeyStructure;
    signingKeyStructure.set_public_(signatureKey.serialize().constData());

    senderKeyStateStructure = textsecure::SenderKeyStateStructure();
    senderKeyStateStructure.set_senderkeyid(id);
    senderKeyStateStructure.mutable_senderchainkey()->CopyFrom(senderChainKeyStructure);
    senderKeyStateStructure.mutable_sendersigningkey()->CopyFrom(signingKeyStructure);*/
}

SenderKeyState::SenderKeyState(int id, int iteration, const QByteArray &chainKey, const ECKeyPair &signatureKey)
{
    SenderKeyState(id, iteration, chainKey, signatureKey.getPublicKey(), signatureKey.getPrivateKey());
}

SenderKeyState::SenderKeyState(int id, int iteration, const QByteArray &chainKey, const DjbECPublicKey &signatureKeyPublic, const DjbECPrivateKey &signatureKeyPrivate)
{
    senderKeyStateStructure = textsecure::SenderKeyStateStructure();
    senderKeyStateStructure.set_senderkeyid(id);
    senderKeyStateStructure.mutable_senderchainkey()->set_iteration(iteration);
    senderKeyStateStructure.mutable_senderchainkey()->set_seed(chainKey.constData(),
                                                               chainKey.size());
    senderKeyStateStructure.mutable_sendersigningkey()->set_public_(signatureKeyPublic.serialize().constData(),
                                                                    signatureKeyPublic.serialize().size());
    senderKeyStateStructure.mutable_sendersigningkey()->set_private_(signatureKeyPrivate.serialize().constData(),
                                                                     signatureKeyPrivate.serialize().size());

    /*textsecure::SenderKeyStateStructure::SenderChainKey senderChainKeyStructure;
    senderChainKeyStructure.set_iteration(iteration);
    senderChainKeyStructure.set_seed(chainKey.constData());

    textsecure::SenderKeyStateStructure::SenderSigningKey signingKeyStructure;
    signingKeyStructure.set_public_(signatureKeyPublic.serialize().constData());

    signingKeyStructure.set_private_(signatureKeyPrivate.serialize().constData());

    senderKeyStateStructure = textsecure::SenderKeyStateStructure();
    senderKeyStateStructure.set_senderkeyid(id);
    senderKeyStateStructure.mutable_senderchainkey()->CopyFrom(senderChainKeyStructure);
    senderKeyStateStructure.mutable_sendersigningkey()->CopyFrom(signingKeyStructure);*/
}

SenderKeyState::SenderKeyState(const textsecure::SenderKeyStateStructure &senderKeyStateStructure)
{
    this->senderKeyStateStructure = senderKeyStateStructure;
}

int SenderKeyState::getKeyId() const
{
    return senderKeyStateStructure.senderkeyid();
}

SenderChainKey SenderKeyState::getSenderChainKey() const
{
    ::std::string seed = senderKeyStateStructure.senderchainkey().seed();
    return SenderChainKey(senderKeyStateStructure.senderchainkey().iteration(),
                          QByteArray(seed.data(), seed.length()));
}

void SenderKeyState::setSenderChainKey(const SenderChainKey &chainKey)
{
    senderKeyStateStructure.mutable_senderchainkey()->set_iteration(chainKey.getIteration());
    senderKeyStateStructure.mutable_senderchainkey()->set_seed(chainKey.getSeed().constData(),
                                                               chainKey.getSeed().size());

    /*textsecure::SenderKeyStateStructure::SenderChainKey senderChainKeyStructure;
    senderChainKeyStructure.set_iteration(chainKey.getIteration());
    senderChainKeyStructure.set_seed(chainKey.getSeed().constData());

    senderKeyStateStructure.mutable_senderchainkey()->CopyFrom(senderChainKeyStructure);*/
}

DjbECPublicKey SenderKeyState::getSigningKeyPublic() const
{
    ::std::string sendersigningkeypublic = senderKeyStateStructure.sendersigningkey().public_();
    return Curve::decodePoint(QByteArray(sendersigningkeypublic.data(), sendersigningkeypublic.length()), 0);
}

DjbECPrivateKey SenderKeyState::getSigningKeyPrivate() const
{
    ::std::string sendersigningkeyprivate = senderKeyStateStructure.sendersigningkey().public_();
    return Curve::decodePrivatePoint(QByteArray(sendersigningkeyprivate.data(), sendersigningkeyprivate.length()));
}

bool SenderKeyState::hasSenderMessageKey(uint32_t iteration) const
{
    for (int i = 0; i < senderKeyStateStructure.sendermessagekeys_size(); i++) {
        textsecure::SenderKeyStateStructure::SenderMessageKey senderMessageKey = senderKeyStateStructure.sendermessagekeys(i);
        if (senderMessageKey.iteration() == iteration) {
            return true;
        }
    }

    return false;
}

void SenderKeyState::addSenderMessageKey(const SenderMessageKey &senderMessageKey)
{
    senderKeyStateStructure.add_sendermessagekeys()->set_iteration(senderMessageKey.getIteration());
    senderKeyStateStructure.add_sendermessagekeys()->set_seed(senderMessageKey.getSeed().constData(),
                                                              senderMessageKey.getSeed().size());

    /*textsecure::SenderKeyStateStructure::SenderMessageKey senderMessageKeyStructure;
    senderMessageKeyStructure.set_iteration(senderMessageKey.getIteration());
    senderMessageKeyStructure.set_seed(senderMessageKey.getSeed().constData());

    senderKeyStateStructure.add_sendermessagekeys()->CopyFrom(senderMessageKeyStructure);*/
}

SenderMessageKey SenderKeyState::removeSenderMessageKey(uint32_t iteration)
{
    SenderMessageKey result;
    for (int i = 0; i < senderKeyStateStructure.sendermessagekeys_size(); i++) {
        textsecure::SenderKeyStateStructure::SenderMessageKey *senderMessageKey = senderKeyStateStructure.mutable_sendermessagekeys(i);
        if (senderMessageKey->iteration() == iteration) {
            ::std::string senderMessageKeySeed = senderMessageKey->seed();
            result = SenderMessageKey(iteration, QByteArray(senderMessageKeySeed.data(), senderMessageKeySeed.length()));
            delete senderMessageKey;
            break;
        }
    }

    return result;
}

textsecure::SenderKeyStateStructure SenderKeyState::getStructure() const
{
    return senderKeyStateStructure;
}
