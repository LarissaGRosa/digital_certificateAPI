package service.labsec_service_challenge.entity;


import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.util.Pair;
import service.labsec_service_challenge.repository.CryptographyRepository;

import java.security.*;
import java.util.Arrays;
import java.util.List;

public class Common {
    @Autowired
    private CryptographyRepository cr;

    public Pair<PrivateKey, PublicKey> getKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair key = keyGen.generateKeyPair();
        PrivateKey priv = key.getPrivate();
        PublicKey pub = key.getPublic();
        Pair<PrivateKey, PublicKey> result;
        result = Pair.of(priv, pub);
        return result;
    }

    public Cryptography saveCrypto(PublicKey pub, PrivateKey priv){

        Cryptography save_crypto = new Cryptography();
        save_crypto.setPrivate_key(java.util.Base64.getEncoder().encodeToString(priv.getEncoded()));
        save_crypto.setPublic_key(java.util.Base64.getEncoder().encodeToString(pub.getEncoded()));
        save_crypto  = cr.saveAndFlush(save_crypto);
        return save_crypto;
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
