TEMPLATE = lib

TARGET = axolotl
isEmpty(CURRENT_RPATH_DIR) {
    target.path = /usr/lib
} else {
    message("$$TARGET QMAKE_RPATHDIR and path is set to $$CURRENT_RPATH_DIR")
    target.path = $$CURRENT_RPATH_DIR
    QMAKE_RPATHDIR += $$INSTALL_ROOT$$CURRENT_RPATH_DIR
}
VERSION = 1.0.0
INSTALLS += target

CONFIG += dll link_pkgconfig
PKGCONFIG += openssl libssl libcrypto protobuf
#CONFIG += staticlib
DEFINES += LIBAXOLOTL_LIBRARY

LIBS += -L../libcurve25519 -lcurve25519

HEADERS += \
    duplicatemessageexception.h \
    invalidkeyexception.h \
    invalidkeyidexception.h \
    invalidmessageexception.h \
    invalidversionexception.h \
    nosessionexception.h \
    stalekeyexchangeexception.h \
    untrustedidentityexception.h \
    ecc/curve.h \
    ecc/eckeypair.h \
    util/byteutil.h \
    ecc/djbec.h \
    kdf/derivedmessagesecrets.h \
    kdf/derivedrootsecrets.h \
    kdf/hkdf.h \
    util/keyhelper.h \
    identitykey.h \
    identitykeypair.h \
    state/prekeybundle.h \
    state/prekeyrecord.h \
    state/LocalStorageProtocol.pb.h \
    state/sessionrecord.h \
    state/sessionstate.h \
    ratchet/messagekeys.h \
    ratchet/aliceaxolotlparameters.h \
    ratchet/bobaxolotlparameters.h \
    ratchet/chainkey.h \
    ratchet/ratchetingsession.h \
    ratchet/symmetricaxolotlparameters.h \
    ratchet/rootkey.h \
    state/sessionstore.h \
    state/signedprekeyrecord.h \
    state/signedprekeystore.h \
    groups/ratchet/senderchainkey.h \
    groups/ratchet/sendermessagekey.h \
    groups/state/senderkeyrecord.h \
    groups/state/senderkeystate.h \
    groups/state/senderkeystore.h \
    protocol/WhisperTextProtocol.pb.h \
    protocol/ciphertextmessage.h \
    protocol/keyexchangemessage.h \
    legacymessageexception.h \
    whisperexception.h \
    protocol/prekeywhispermessage.h \
    protocol/whispermessage.h \
    protocol/senderkeymessage.h \
    protocol/senderkeydistributionmessage.h \
    sessioncipher.h \
    sessionbuilder.h \
    state/prekeystore.h \
    state/axolotlstore.h \
    state/identitykeystore.h \
    util/medium.h \
    axolotl_global.h

SOURCES += \
    ecc/curve.cpp \
    ecc/eckeypair.cpp \
    util/byteutil.cpp \
    ecc/djbec.cpp \
    kdf/derivedmessagesecrets.cpp \
    kdf/derivedrootsecrets.cpp \
    kdf/hkdf.cpp \
    util/keyhelper.cpp \
    identitykey.cpp \
    identitykeypair.cpp \
    state/prekeybundle.cpp \
    state/prekeyrecord.cpp \
    state/LocalStorageProtocol.pb.cc \
    state/sessionrecord.cpp \
    state/sessionstate.cpp \
    ratchet/messagekeys.cpp \
    ratchet/aliceaxolotlparameters.cpp \
    ratchet/bobaxolotlparameters.cpp \
    ratchet/chainkey.cpp \
    ratchet/ratchetingsession.cpp \
    ratchet/symmetricaxolotlparameters.cpp \
    ratchet/rootkey.cpp \
    state/signedprekeyrecord.cpp \
    groups/ratchet/senderchainkey.cpp \
    groups/ratchet/sendermessagekey.cpp \
    groups/state/senderkeyrecord.cpp \
    groups/state/senderkeystate.cpp \
    protocol/WhisperTextProtocol.pb.cc \
    protocol/keyexchangemessage.cpp \
    protocol/prekeywhispermessage.cpp \
    protocol/whispermessage.cpp \
    protocol/senderkeymessage.cpp \
    protocol/senderkeydistributionmessage.cpp \
    sessioncipher.cpp \
    sessionbuilder.cpp
