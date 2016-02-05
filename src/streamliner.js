var openpgp = typeof window != 'undefined' && window.openpgp ? window.openpgp : require('../node_modules/openpgp/src/index.js');

module.exports = gpgUserId = function(pubkeyarmor) {
    var publicKey = openpgp.key.readArmored(pubkeyarmor);
    return publicKey.keys[0].users[0].userId.userid;
};

module.exports = gpgMsgDecrypt = function (encryptedmsgarmor, receiverprivkeyarmor, senderpubkeyarmor){
    var privateKey = openpgp.key.readArmored(receiverprivkeyarmor).keys[0];
    privateKey.decrypt('');
    var publicKeys = openpgp.key.readArmored(senderpubkeyarmor).keys;
    var encryptedmsg = openpgp.message.readArmored(encryptedmsgarmor);
    return openpgp.decryptAndVerifyMessage(privateKey, publicKeys, encryptedmsg);
};

module.exports = gpgMsgEncrypt = function (receiverpubkeyarmor, plaintextmsg){
    var receiverpubkey = openpgp.key.readArmored(receiverpubkeyarmor);
    var plaintext = plaintextmsg;
    return openpgp.encryptMessage(receiverpubkey.keys, plaintext).then(function(pgpMessage) {
        return(pgpMessage);
    }).catch(function(error) {
        // failure
    });
};