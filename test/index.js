'use strict';

process.env.NODE_ENV = 'test';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

var fs = require('fs');
var ssloptions = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt')
}
var https = require('https');
var cheerio = require('cheerio');

suite('index:', function(done) {
    
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

    before(function () {
    });

    var request = require('request');
    var eventFired = false;
    var assert = require("assert");
    test('this always passes', function() {
        assert.equal(1, 1);
    });
    test('Testing with callback (asynchronous)', function (done) {
        setTimeout(completeWhenThisExecutes, 100)
        function completeWhenThisExecutes() {
            done();
        }
    });
    test('check pulse https should return statusCode 200', function (done) {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
        var req = https.request(
            {
                host: config.app_host,
                path: '/',
                port: config.https_port,
                rejectUnauthorized: false,
                requestCert: false,
                agent: false
            }, function(res){
                var body = [];
                res.on('data', function(data){
                    body.push(data);
                });
                res.on('end', function(){
                    assert.equal(res.statusCode, 200);
                });
            });
            req.end();
            req.on('error', function(err){
        });
        done()
    });

    test('server gpg public key matches config', function (done) {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
        var req = https.request(
            {
                host: config.app_host,
                path: '/',
                port: config.https_port,
                rejectUnauthorized: false,
                requestCert: false,
                agent: false
            }, function(res){
                res.setEncoding('utf8');
                var spool = '';
                res.on('data', function(data){
                    spool += data;
                });
                res.on('end', function(){
                    if (res.statusCode == 200) {
                        var cheers = cheerio.load(spool);
                        var pubkeyfromconfig = '\n' + fs.readFileSync(config.server_pub_key,  'utf8') + '\n            ';
                        assert.equal( pubkeyfromconfig, cheers('textarea').html());
                    }
                    done();
                });
            });
        req.end();
        req.on('error', function(err){
        });
    });

    test('server public key deliverered in html is useful for encryption', function (done) {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

        var teststring = config.test_string;
        var req = https.request(
            {
                host: config.app_host,
                path: '/',
                port: config.https_port,
                rejectUnauthorized: false,
                requestCert: false,
                agent: false
            }, function(res){
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
                        openpgp.encryptMessage(publicKey.keys, config.test_string).then(function(pgpMessageArmor) {
                            var secretmsg = openpgp.message.readArmored(pgpMessageArmor);
                            openpgp.decryptMessage(privateKey, secretmsg).then(function(cleartext){
                                assert.equal(cleartext, config.test_string)
                                done();
                            });
                        });
                    }
                });
            });
        req.end();
        req.on('error', function(err){
        });
    });
    server.on( 'request' , function (data) {
      eventFired = true;
    });
    server.on( 'error' , function (e) {
        eventFired = true;
        var message = e.message;
        if (message != "listen EADDRINUSE") {
            console.log("Got error: " + e.message);
        }
    });
    after(function () {
      eventFired = false;
    });
});
