package service.labsec_service_challenge.entity;

import org.bouncycastle.asn1.*;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import service.labsec_service_challenge.controller.CertController;
import org.springframework.beans.factory.annotation.Autowired;
import service.labsec_service_challenge.repository.CertificateRepository;

public class Authority {

    public X509Certificate makeCertificate(PublicKey pk, int serialNumber, String n,
                                           String ac, PrivateKey privatek,
                                           AlgorithmIdentifier signaturealgo) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, CertificateParsingException {
        V3TBSCertificateGenerator g = new V3TBSCertificateGenerator();
        g.setSerialNumber(new ASN1Integer(serialNumber));
        g.setIssuer(new X500Name(n));
        g.setSubject(new X500Name(ac));
        g.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pk.getEncoded()));
        g.setSignature(new AlgorithmIdentifier(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.rsaEncryption.getId())));
        long date = System.currentTimeMillis();
        g.setStartDate(new Time(new Date(date)));
        g.setEndDate(new Time(new Date(date + 10 * 86400000l)));
        Signature signature = Signature.getInstance("SHA512withRSA");
        TBSCertificate tbs = g.generateTBSCertificate(); 
        signature.initSign(privatek);
        signature.update(tbs.getEncoded(ASN1Encoding.DER));
        DERBitString der = new DERBitString(signature.sign());
        ASN1EncodableVector encodableVector = new ASN1EncodableVector();
        encodableVector.add(tbs);
        encodableVector.add(signaturealgo);
        encodableVector.add(der);
        return new X509CertificateObject(Certificate.getInstance(new DERSequence(encodableVector)));
    }

}
