const { PDFNet } = require('@pdftron/pdfnet-node');
const { GlobalSignAPI } = require('./api')
const { license_key } = require('./license-key.json')
const path = require('path');

const api = new GlobalSignAPI();;
const IN_FILE = "digital-signature.pdf";
const OUT_FILE = "digital-signature-signed.pdf";

const { PDFDoc, SDFDoc, X509Certificate, DigitalSignatureField, DigestAlgorithm, VerificationOptions } = PDFNet;


const main = async () =>{

    await api.login();
    await api.createSigningIdentity();
    await api.loadSigningCertificate();
    await api.loadTrustChain();

    const doc = await PDFDoc.createFromFilePath(IN_FILE);

    //create certificate
    const signer_cert = await X509Certificate.createFromBuffer(api.signing_cert_buffer);
    const chain_certs = api.chain_certs;

    //Get the digital signature field
    const signature_field = await doc.getField("SignatureFormField 1");
    const digital_signature_field = await DigitalSignatureField.createFromField(signature_field);
    const is_locked = await signature_field.isLockedByDigitalSignature();
    
    if(is_locked){
        console.log("The field is locked by a Digital Signature, and thus cannot be Digitally Signed again")
        return;
    }

    // Create a digital signature dictionary inside the digital signature field, in preparation for signing.
    await digital_signature_field.createSigDictForCustomSigning(
        "Adobe.PPKLite",
        PDFNet.DigitalSignatureField.SubFilterType.e_adbe_pkcs7_detached,
        7500
    );

    await doc.save(OUT_FILE, SDFDoc.SaveOptions.e_incremental);
    
    const pdf_digest = await digital_signature_field.calculateDigest(DigestAlgorithm.Type.e_SHA256);
    const pades_versioned_ess_signing_cert_attribute = await PDFNet.DigitalSignatureField.generateESSSigningCertPAdESAttribute(signer_cert, PDFNet.DigestAlgorithm.Type.e_SHA256);
    
    // generate the signedAttrs component of CMS
    const signed_attributes = await PDFNet.DigitalSignatureField.generateCMSSignedAttributes(pdf_digest, pades_versioned_ess_signing_cert_attribute);
    
    // Calculate the digest of the signedAttrs (i.e. not the PDF digest, this time).
    const signed_attributes_digest = await PDFNet.DigestAlgorithm.calculateDigest(PDFNet.DigestAlgorithm.Type.e_SHA256, signed_attributes);
    const digest_buffer = Buffer.from(signed_attributes_digest).toString('hex').toUpperCase();
    const signature_buffer = await api.signDigest(digest_buffer);

    // Create the OIDs for the algorithms you have used.
    const digest_algorithm_oid = await PDFNet.ObjectIdentifier.createFromDigestAlgorithm(PDFNet.DigestAlgorithm.Type.e_SHA256);
    const signature_algorithm_oid = await PDFNet.ObjectIdentifier.createFromIntArray([1, 2, 840, 113549, 1, 1]);

    const cms_signature = await PDFNet.DigitalSignatureField.generateCMSSignature(signer_cert, chain_certs, digest_algorithm_oid, signature_algorithm_oid, signature_buffer, signed_attributes);
    doc.saveCustomSignature(cms_signature, digital_signature_field, OUT_FILE);

    // Verify
	const opts = await VerificationOptions.create(VerificationOptions.SecurityLevel.e_compatibility_and_archiving);
	await opts.addTrustedCertificateUString(path.resolve(__dirname, './certs/mTLS.cer'));
	const result = await doc.verifySignedDigitalSignatures(opts);
    console.log("Verfication:", result);
}

PDFNet.runWithCleanup(main, license_key)
    .catch((err) => console.log("Error:", err))
    .then(() => PDFNet.shutdown());