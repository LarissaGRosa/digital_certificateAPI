package service.labsec_service_challenge.entity;


import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

import javax.persistence.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

@Entity
@Table(name = "Certificate", uniqueConstraints = {
        @UniqueConstraint(columnNames = "name")
})
public class CertificateCA
{
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "authority_id",nullable = false)
    private Authority issuer;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User certowner;

    @Column(nullable = false)
    private Boolean isValid;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String subject;

    public User getCert_owner() {
        return certowner;
    }

    public void setCert_owner(User cert_owner) {
        this.certowner = cert_owner;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getId() {
        return id;
    }

    public Authority getIssuer() {
        return issuer;
    }

    public String getSubject(){return subject;}

    public void setIssuer(Authority nome) {
        this.issuer = nome;
    }

    public void setId(long id) {
        this.id = id;
    }


    public void setSubject(String subject){this.subject = subject;}

    public Boolean getValid() {
        return isValid;
    }

    public void setValid(Boolean valid) {
        isValid = valid;
    }

    public X509Certificate makeCertificate(PublicKey pk, int serialNumber, PrivateKey privatek,
                                           AlgorithmIdentifier signaturealgo, X500Name subject, X500Name issuer) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, CertificateParsingException {
        V3TBSCertificateGenerator g = new V3TBSCertificateGenerator();
        g.setSerialNumber(new ASN1Integer(serialNumber));
        g.setIssuer(issuer);
        g.setSubject(subject);
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

