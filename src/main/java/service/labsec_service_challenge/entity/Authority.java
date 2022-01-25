package service.labsec_service_challenge.entity;

import org.bouncycastle.asn1.*;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

import java.io.IOException;
import java.security.*;
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


    @Column(nullable = false)
    private String data_location;

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

    public String getData_location() {
        return data_location;
    }

    public void setData_location(String data_location) {
        this.data_location = data_location;
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

    public X500Name subject_create(String CN, String OU, String O, String
                                   L, String ST, String C, String UI){
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBld.addRDN(BCStyle.CN,  CN);
        x500NameBld.addRDN(BCStyle.OU, OU);
        x500NameBld.addRDN(BCStyle.O, O);
        x500NameBld.addRDN(BCStyle.L, L);
        x500NameBld.addRDN(BCStyle.ST, ST);
        x500NameBld.addRDN(BCStyle.C, C);
        x500NameBld.addRDN(BCStyle.UNIQUE_IDENTIFIER, UI);
        X500Name subject = x500NameBld.build();
        return subject;
    }
    public X500Name subject_load(String items){
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        List<String> data = Arrays.asList(items.split(","));
        String CN = Arrays.asList(data.get(0).split("=")).get(1);
        String OU = Arrays.asList(data.get(1).split("=")).get(1);
        String O = Arrays.asList(data.get(2).split("=")).get(1);
        String L = Arrays.asList(data.get(3).split("=")).get(1);
        String ST = Arrays.asList(data.get(4).split("=")).get(1);
        String C = Arrays.asList(data.get(5).split("=")).get(1);
        String UI = Arrays.asList(data.get(6).split("=")).get(1);
        x500NameBld.addRDN(BCStyle.CN,  CN);
        x500NameBld.addRDN(BCStyle.OU, OU);
        x500NameBld.addRDN(BCStyle.O, O);
        x500NameBld.addRDN(BCStyle.L, L);
        x500NameBld.addRDN(BCStyle.ST, ST);
        x500NameBld.addRDN(BCStyle.C, C);
        x500NameBld.addRDN(BCStyle.UNIQUE_IDENTIFIER, UI);
        X500Name subject = x500NameBld.build();
        return subject;
    }




}
