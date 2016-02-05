'use strict';

var koa = require('koa');
var config = require(__dirname + '/config/options.js');
var forceSSL = require('koa-force-ssl');
var app = koa();
var fs = require('fs');
var logger = require('koa-logger');
var route = require('koa-route');
var views = require('co-views');
var serve = require('koa-static');
var http = require('http');
var https = require('https');
var openpgp = require('openpgp');
var parse = require('co-body');
var uuid = require('node-uuid');

app.use(logger());
app.use(forceSSL());

var render= views(__dirname + '/views',
{ map: { html: 'swig' }});

var ssloptions = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt')
};

function *index() {
    this.body = yield render('index' , {
        'serverpublicgpgkeyarmor': fs.readFileSync(config.server_pub_key,  "utf8"),
    });
};

function *identify() {
    var encryptedClientPubkey = 'xxx';
    var clientPubKeyArmor = '';
    var postedcontent = yield parse.form(this);
    var gpgprivkeyarmor = fs.readFileSync(config.server_private_key,  "utf8");
    var privateKey = openpgp.key.readArmored(gpgprivkeyarmor);
    var privateKeyZero = privateKey.keys[0];
    privateKeyZero.decrypt(config.demo_client_private_key_password);
    var pgpMessageArmor = postedcontent.outbox;
    var pgpMessage = openpgp.message.readArmored(pgpMessageArmor);
    var SignedEncryptedClientPubkey = yield openpgp.decryptMessage(privateKeyZero, pgpMessage).then(function(plaintext) {
        var receiverpubkey = openpgp.key.readArmored(plaintext).keys[0];
        return openpgp.signAndEncryptMessage(receiverpubkey, privateKeyZero, plaintext).then(function(encryptedSignedText) {
            return encryptedSignedText;
        });
    });
    this.body = yield render('identify' , { 
        'uniqueid': uuid.v1(),
        'encrypted_msg_armor': SignedEncryptedClientPubkey,
        'server_public_gpg_key_armor': fs.readFileSync(config.server_pub_key,  "utf8")
    });
};

app.use(route.get('/', index));
app.use(route.post('/identify', identify));

app.use(serve(config.public_dir));

http.createServer(app.callback()).listen(config.http_port);
var server = module.exports = https.createServer(ssloptions, app.callback()).listen(config.https_port);