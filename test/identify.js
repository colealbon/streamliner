'use strict';

process.env.NODE_ENV = 'test';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

var fs = require('fs');
var ssloptions = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt')
}
var http = require('http');
var https = require('https');
var cheerio = require('cheerio');

suite('identify:', function(done) {

    function check( done, f ) {
      try {
        f()
        done()
      } catch( e ) {
        done( e )
      }
    };

    var server = require('../app.js');
    var config = require(__dirname + '/../config/options.js');
    if (!server) server = https.createServer(ssloptions);
    var eventFired = false;
    var assert = require("assert");

    test('server responds to posted encrypted pubkey', function (done) {

        var afterLanding = function(res){
            res.setEncoding('utf8');
            var spool = '';
            res.on('data', function(data){
                spool += data;
            });
            res.on('end', function(){
                if (res.statusCode == 200) {
                    var cheers = cheerio.load(spool);
                    var serverpublicgpgkeyarmor = cheers('span.serverpublicgpgkeyarmor').text();
                    var openpgp = require('openpgp');
                    var publicKey = openpgp.key.readArmored(serverpublicgpgkeyarmor);
                    var privateKey = openpgp.key.readArmored(fs.readFileSync(config.server_private_key, 'utf8')).keys[0];
                    privateKey.decrypt();
                    openpgp.encryptMessage(publicKey.keys, fs.readFileSync(config.test_client_pub_key, 'utf8')).then(function(pgpMessageArmor) {
                        var secretmsg = openpgp.message.readArmored(pgpMessageArmor);
                        openpgp.decryptMessage(privateKey, secretmsg).then(function(cleartext){
                            assert.equal(cleartext, fs.readFileSync(config.test_client_pub_key, 'utf8'));
                            var querystring = require('querystring');
                            var post_data = querystring.stringify({outbox: pgpMessageArmor});
                            var post_identify = https.request(
                                {
                                    host: config.app_host,
                                    path: '/identify',
                                    port: config.https_port,
                                    rejectUnauthorized: false,
                                    requestCert: false,
                                    agent: false,
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'Content-Length': post_data.length
                                    }
                                }, afterIdentify)
                                .write(post_data)
                                .end();
                        });
                    });
                }
            });
        };
        var afterIdentify = function(res){
            var baseline;
            var testsubject;
            res.setEncoding('utf8');
            var spool = '';
            res.on('data', function(data){
                spool += data;
            });
            res.on('end', function(){
                var baseline;
                var testsubject;
                if (res.statusCode == 200) {
                    var cheers = cheerio.load(spool);
                    var serverpublicgpgkeyarmor = cheers('span.server_public_gpg_key_armor').text();
                    var secretmsgarmor = cheers('span.encrypted_msg_armor').text();
                    var openpgp = require('openpgp');
                    var publicKey = openpgp.key.readArmored(serverpublicgpgkeyarmor);
                    var privateKey = openpgp.key.readArmored(fs.readFileSync(config.test_client_private_key, 'utf8')).keys[0];
                    privateKey.decrypt();
                    var secretmsg = openpgp.message.readArmored(secretmsgarmor);
                    testsubject = fs.readFileSync(config.test_client_pub_key, 'utf8');
                    openpgp.decryptMessage(privateKey, secretmsg).then(function(cleartext){
                        //console.log(cleartext);
                        //return cleartext;
                        check( done, function() {
                            assert.equal(cleartext, testsubject);
                            //done();
                            //expect(pgpMessage.text).to.equal(cleartextmsg);
                        }, 100);
                    });

                }
            });
            }

        var landingStart = https.request(
            {
                host: config.app_host,
                path: '/',
                port: config.https_port,
                rejectUnauthorized: false,
                requestCert: false,
                agent: false
            }, afterLanding).end();
    });
});
