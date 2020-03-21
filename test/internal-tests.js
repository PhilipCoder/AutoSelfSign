const assert = require('chai').assert;
const autoSelfSign = require("../autoSelfSign.js");
const path = require("path");
const fs = require("fs");
const https = require("https");
const exec = require('child_process').exec

describe('internal-test', function () {
    it('checkCertFiles', async function () {
        let config = getConfig();

        let checkCertificates = await autoSelfSign.internal.checkCertFiles(config);
        assert(checkCertificates.cert.fileExists === false, "Cert file should not exist.");
        assert(checkCertificates.key.fileExists === false, "Key file should not exist.");
        assert(checkCertificates.pkcs12.fileExists === false, "pkcs12 file should not exist.");
        assert(checkCertificates.pkcs12.filePath === null, "pkcs12 file should not exist.");

        fs.writeFileSync(checkCertificates.cert.filePath, "File");
        checkCertificates = await autoSelfSign.internal.checkCertFiles(config);
        assert(checkCertificates.cert.fileExists === true, "Cert file should not exist.");
        assert(checkCertificates.key.fileExists === false, "Key file should not exist.");
        assert(checkCertificates.pkcs12.fileExists === false, "pkcs12 file should not exist.");
        assert(checkCertificates.pkcs12.filePath === null, "pkcs12 file should not exist.");
        fs.unlinkSync(checkCertificates.cert.filePath);

        fs.writeFileSync(checkCertificates.key.filePath, "File");
        checkCertificates = await autoSelfSign.internal.checkCertFiles(config);
        assert(checkCertificates.cert.fileExists === false, "Cert file should not exist.");
        assert(checkCertificates.key.fileExists === true, "Key file should not exist.");
        assert(checkCertificates.pkcs12.fileExists === false, "pkcs12 file should not exist.");
        assert(checkCertificates.pkcs12.filePath === null, "pkcs12 file should not exist.");
        fs.unlinkSync(checkCertificates.key.filePath);

        let p12File = path.join(config.certificateFolder, `${config.pkcs12CertFileName}_localhost.p12`);
        fs.writeFileSync(p12File, "File");
        checkCertificates = await autoSelfSign.internal.checkCertFiles(config);
        assert(checkCertificates.cert.fileExists === false, "Cert file should not exist.");
        assert(checkCertificates.key.fileExists === false, "Key file should not exist.");
        assert(checkCertificates.pkcs12.fileExists === true, "pkcs12 file should not exist.");
        assert(checkCertificates.pkcs12.filePath === p12File, "pkcs12 file incorrect.");
        fs.unlinkSync(p12File);
    });

    it('validateConfig', async function () {
        let config = getConfig();

        autoSelfSign.internal.validateConfig(config);

        config.certificateFolder = "c:\\someRandomFolderX";
        assert.throw(() => autoSelfSign.internal.validateConfig(config), "Cert directory \"c:\\someRandomFolderX\" does not exist.");
    });

    it('generatePKCS12', async function () {
        let config = getConfig();
        let checkCertificates = await autoSelfSign.internal.checkCertFiles(config);

        assert(checkCertificates.cert.fileExists === false, "Cert file should not exist.");
        assert(checkCertificates.key.fileExists === false, "Key file should not exist.");
        assert(checkCertificates.pkcs12.fileExists === false, "pkcs12 file should not exist.");
        assert(checkCertificates.pkcs12.filePath === null, "pkcs12 file should not exist.");

        await autoSelfSign.internal.generatePKCS12(checkCertificates, config);

        checkCertificates = await autoSelfSign.internal.checkCertFiles(config);

        assert(checkCertificates.cert.fileExists === false, "Cert file should not exist.");
        assert(checkCertificates.key.fileExists === false, "Key file should not exist.");
        assert(checkCertificates.pkcs12.fileExists === true, "pkcs12 file should not exist.");
        assert(checkCertificates.pkcs12.filePath !== null, "pkcs12 file should exist.");
        fs.unlinkSync(checkCertificates.pkcs12.filePath);
    });

    it('generateCert', async function () {
        let config = getConfig();
        let certFileStats = await autoSelfSign.internal.checkCertFiles(config);
        await autoSelfSign.internal.generatePKCS12(certFileStats, config);
        let certStatsPKCS12 = await autoSelfSign.internal.checkCertFiles(config);

        let certificateValues = await autoSelfSign.internal.generateCert(certFileStats, certStatsPKCS12);

        assert(certificateValues.cert.startsWith("-----BEGIN CERTIFICATE-----"), "Invalid certificate generated!");
        assert(certificateValues.key.startsWith("-----BEGIN RSA PRIVATE KEY-----"), "Invalid private key generated!");

        fs.unlinkSync(certStatsPKCS12.pkcs12.filePath);
    });

    it('autoSelfSign-no-install', async function () {
        let config = getConfig();
        config.installCertWindows = false;
        let generationResult = await autoSelfSign.autoSelfSign(config);

        let certFileStats = await autoSelfSign.internal.checkCertFiles(config);
        assert(certFileStats.cert.fileExists === true, "Cert file should exist.");
        assert(certFileStats.key.fileExists === true, "Key file should exist.");
        assert(certFileStats.pkcs12.fileExists === true, "pkcs12 file should exist.");
        assert(certFileStats.pkcs12.filePath !== null, "pkcs12 file should exist.");
        assert(generationResult.cert.startsWith("-----BEGIN CERTIFICATE-----"), "Invalid certificate generated!");
        assert(generationResult.key.startsWith("-----BEGIN RSA PRIVATE KEY-----"), "Invalid private key generated!");

        fs.unlinkSync(certFileStats.pkcs12.filePath);
        fs.unlinkSync(certFileStats.cert.filePath);
        fs.unlinkSync(certFileStats.key.filePath);

    });

    //Commented out because it actually installs the certificate. Uncomment to test.

    // it('autoSelfSign-install', async function () {
    //     let config = getConfig();
    //     let generationResult = await autoSelfSign.autoSelfSign(config);

    //     let certFileStats = await autoSelfSign.internal.checkCertFiles(config);
    //     assert(certFileStats.cert.fileExists === true, "Cert file should exist.");
    //     assert(certFileStats.key.fileExists === true, "Key file should exist.");
    //     assert(certFileStats.pkcs12.fileExists === true, "pkcs12 file should exist.");
    //     assert(certFileStats.pkcs12.filePath !== null, "pkcs12 file should exist.");
    //     assert(generationResult.cert.startsWith("-----BEGIN CERTIFICATE-----"),"Invalid certificate generated!");
    //     assert(generationResult.key.startsWith("-----BEGIN RSA PRIVATE KEY-----"),"Invalid private key generated!");

    //     fs.unlinkSync(certFileStats.pkcs12.filePath);
    //     fs.unlinkSync(certFileStats.cert.filePath);
    //     fs.unlinkSync(certFileStats.key.filePath);

    // });

    // it('autoSelfSign-test-server', async function () {
    //     this.timeout = 30000;
    //     let config = getConfig();
    //     let generationResult = await autoSelfSign.autoSelfSign(config);
        
    //     //create HTTPS server
    //     let serverRequest = function (request, response) {
    //         response.writeHead("200");
    //         response.end("Test SSL response");
    //     }
    //     const options = {
    //         key: generationResult.key,
    //         cert: generationResult.cert
    //     };
    //     let server = https.createServer(options, serverRequest).listen(8580);

    //     //open chrome
    //     exec('start chrome https://localhost:8580', function (err) { });
    //     //cleanup certs
    //     let certFileStats = await autoSelfSign.internal.checkCertFiles(config);
    //     fs.unlinkSync(certFileStats.pkcs12.filePath);
    //     fs.unlinkSync(certFileStats.cert.filePath);
    //     fs.unlinkSync(certFileStats.key.filePath);
    //     setTimeout(() => {
    //         server.close();
    //     }, 4000);
    // });

})

function getConfig() {
    let certificateDir = path.join(__dirname, "certificates");
    let configSource = autoSelfSign.config;
    let config = {};
    Object.assign(config, configSource);
    config.certificateFolder = certificateDir;
    return config;
}
