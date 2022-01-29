package service.labsec_service_challenge.entity;
import org.springframework.data.util.Pair;
import org.bouncycastle.asn1.*;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.encoders.Base64;

import service.labsec_service_challenge.payloads.SubjectRequest;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.persistence.*;

@Entity
@Table(name = "Authority", uniqueConstraints = {
        @UniqueConstraint(columnNames = "name")
})
public class Authority {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String subject;

    @Column(nullable = false)
    private Boolean isValid;

    @Column(nullable = false, length=10485760)
    private String Certdata;


    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "crypto_id", referencedColumnName = "id")
    private Cryptography crypto;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User owner;

    @OneToMany(mappedBy = "issuer", fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    private Set<CertificateCA> cert;

    public Authority(){

    }

    public Set<CertificateCA> getCert() {
        return cert;
    }

    public void setCert(Set<CertificateCA> cert) {
        this.cert = cert;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }


    public Cryptography getCrypto() {
        return crypto;
    }

    public void setCrypto(Cryptography crypto) {
        this.crypto = crypto;
    }

    public User getOwner() {
        return owner;
    }

    public void setOwner(User owner) {
        this.owner = owner;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Boolean getValid() {
        return isValid;
    }

    public void setValid(Boolean valid) {
        isValid = valid;
    }

    public String getCertdata() {
        return Certdata;
    }

    public void setCertdata(String certdata) {
        Certdata = certdata;
    }

    public X509Certificate makeCertificate(PublicKey pk, int serialNumber, PrivateKey privatek,
                                           AlgorithmIdentifier signaturealgo, X500Name subject) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, CertificateParsingException {


        V3TBSCertificateGenerator g = new V3TBSCertificateGenerator();
        g.setSerialNumber(new ASN1Integer(serialNumber));
        g.setIssuer(subject);
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


    public void create_and_save_cert(SubjectRequest sr) throws CertificateEncodingException, NoSuchAlgorithmException, CertificateParsingException, SignatureException, IOException, InvalidKeyException {
        Common utils = new Common();
        Pair<PrivateKey,PublicKey> keys = utils.getKeyPair();
        X500Name subject = utils.subject_create(sr.getCN(), sr.getOU(), sr.getO(), sr.getL(), sr.getST(), sr.getC(), sr.getUI());
        X509Certificate cert = this.makeCertificate(keys.getSecond(), 1, keys.getFirst(), new AlgorithmIdentifier(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())), subject);
        org.bouncycastle.util.encoders.Base64 encoder = new Base64();

        this.setCrypto(new Cryptography());
        this.getCrypto().setPrivate_key(java.util.Base64.getEncoder().encodeToString(keys.getFirst().getEncoded()));
        this.getCrypto().setPublic_key(java.util.Base64.getEncoder().encodeToString(keys.getSecond().getEncoded()));
        this.setSubject(String.valueOf(subject));
        byte[] derCert = cert.getEncoded();
        String pemCertPre = new String(encoder.encode(derCert));
        String pemCert = pemCertPre;
        this.setCertdata(pemCert);

    }


}
