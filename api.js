const { PDFNet } = require('@pdftron/pdfnet-node');
const axios = require("axios").default;
const https = require("https");
const fs = require('fs');
const path = require('path');
const {api_key, api_secret, passphrase} = require('./config.json');

const DSS_URL = 'https://emea.api.dss.globalsign.com:8443/v2';

const httpsAgent = new https.Agent({
    cert: fs.readFileSync(path.resolve(__dirname, './certs/mTLS.cer')),
    key: fs.readFileSync(path.resolve(__dirname, './certs/private_key.pem')),
    passphrase: passphrase
})

axios.defaults.httpsAgent = httpsAgent;

const GlobalSignAPI = class{
 
    login = () => {
        return new Promise(async (resolve, reject) =>{
            let config = {
                headers: {
                    'Content-Type': 'application/json;charset=UTF-8',
                }
            };

            let data = {
                api_key: api_key, 
                api_secret: api_secret
            }

            try {
                const response = await axios.post(`${DSS_URL}/login`, data, config)
                this.access_token = response.data.access_token;
                resolve();
            } catch (error) {
                reject(error);
            }
        })
    }


    createSigningIdentity = () =>{
        return new Promise(async (resolve, reject) =>{

            let config = {
                headers: {
                    'Content-Type': 'application/json;charset=UTF-8',
                    'Authorization': `Bearer ${this.access_token}`
                }
            };
            
            //info for organization certificate has been prepopulated so we send an empty request
            let data = {}

            try {
                const response = await axios.post(`${DSS_URL}/identity`, data, config);

                this.signing_id = response.data.id;
                this.signing_cert = response.data.signing_cert;
                this.signing_cert_buffer = Buffer.from(response.data.signing_cert, 'utf-8');
                this.ocsp_response = response.data.ocsp_response;
                resolve();
            } catch (error) {
                console.log(error)
                reject(error);
            }
        })
    }

    loadTrustChain = () =>{
        const { X509Certificate } = PDFNet;

        return new Promise(async (resolve, reject) =>{

            let config = {
                headers: {
                    'Content-Type': 'application/json;charset=UTF-8',
                    'Authorization': `Bearer ${this.access_token}`
                }
            };
            
            try {
                const response = await axios.get(`${DSS_URL}/trustchain`, config);
                this.chain_certs = [];

                const certs = response.data.trustchain[0].split(',');

                for (var i = 0; i < certs.length; i++) {
                    const cert_buffer = Buffer.from(certs[i], 'utf-8');
                    const cert = await X509Certificate.createFromBuffer(cert_buffer);
                    this.chain_certs.push(cert);
                }
                
                resolve();
            } catch (error) {
                reject(error);
            }
        })
    }

    loadSigningCertificate = () =>{
        return new Promise(async (resolve, reject) =>{

            let config = {
                headers: {
                    'Content-Type': 'application/json;charset=UTF-8',
                    'Authorization': `Bearer ${this.access_token}`
                }
            };
            
            try {
                const response = await axios.get(`${DSS_URL}/certificate_path`, config);
                this.signing_ca_cert = response.data.path;
                this.signing_ca_cert_buffer = Buffer.from(response.data.path, 'utf-8');
                resolve();
            } catch (error) {
                console.log(error)
                reject(error);
            }
        })
    }

    //returns the digest signature
    signDigest = (digest) =>{
        return new Promise(async (resolve, reject) =>{
            let config = {
                headers: {
                    'Content-Type': 'application/json;charset=UTF-8',
                    'Authorization': `Bearer ${this.access_token}`
                }
            };
            
            try {
                const response = await axios.get(`${DSS_URL}/identity/${this.signing_id}/sign/${digest}`, config)
                const signatureHex = response.data.signature;
                resolve(Buffer.from(signatureHex, 'hex'));
            } catch (error) {
                console.log(error)
                reject(error);
            }
        })
    }


}

module.exports = { GlobalSignAPI }