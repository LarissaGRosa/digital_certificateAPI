package service.labsec_service_challenge.entity;


import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.encoders.Base64;
import service.labsec_service_challenge.payloads.SubjectRequest;
import org.springframework.data.util.Pair;
import javax.persistence.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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

    @Column(nullable = false, length=10485760 )
    private String certdata;

    public User getCert_owner() {
        return certowner;
    }

    public String getCertdata() {
        return certdata;
    }

    public User getCertowner() {
        return certowner;
    }

    public void setCertowner(User certowner) {
        this.certowner = certowner;
    }

    public void setCertdata(String certdata) {
        this.certdata = certdata;
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

    public void create_and_save_cert(SubjectRequest sr, Authority a) throws CertificateEncodingException, NoSuchAlgorithmException, CertificateParsingException, SignatureException, IOException, InvalidKeyException, InvalidKeySpecException {
        Common utils = new Common();
        Pair<PrivateKey,PublicKey> keys = utils.getKeyPair();
        X500Name issuer = utils.subject_load(a.getSubject());
        X500Name subject = utils.subject_create(sr.getCN(), sr.getOU(), sr.getO(), sr.getL(), sr.getST(), sr.getC(), sr.getUI());
        byte[] keyBytes = java.util.Base64.getDecoder().decode(a.getCrypto().getPrivate_key());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                keyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        X509Certificate cert = this.makeCertificate(keys.getSecond(), 1, privateKey, new AlgorithmIdentifier(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())), subject, issuer);
        org.bouncycastle.util.encoders.Base64 encoder = new Base64();

        this.setSubject(String.valueOf(subject));
        byte[] derCert = cert.getEncoded();
        String pemCertPre = new String(encoder.encode(derCert));
        String pemCert = pemCertPre;
        this.setCertdata(pemCert);

    }

}

