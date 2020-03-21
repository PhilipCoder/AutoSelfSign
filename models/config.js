/**
 * Configuration object to configure SSL generation.
 * 
 * Author: Philip Schoeman
 */
let config = {
    certificateFolder: null,
    installCertWindows: true,

    pkcs12CertFileName: "certP12",
    certFileName: "cert",
    keyFileName: "key"
};

module.exports = config;