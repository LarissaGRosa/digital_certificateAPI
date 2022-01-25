package service.labsec_service_challenge.entity;
import org.json.JSONException;
import org.json.JSONObject;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.persistence.*;
import java.io.IOException;
import java.security.*;


@Entity
@Table(name = "Cryptography")
public class Cryptography {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @Column(nullable = false, length=10485760)
    private String public_key;

    @Column(nullable = false, length=10485760)
    private String private_key;

    @OneToOne(mappedBy = "crypto")
    private Authority auth;

    public Cryptography(){}

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getPublic_key() {
        return public_key;
    }

    public void setPublic_key(String public_key) {
        this.public_key = public_key;
    }

    public String getPrivate_key() {
        return private_key;
    }

    public void setPrivate_key(String private_key) {
        this.private_key = private_key;
    }

    public Authority getAuth() {
        return auth;
    }

    public void setAuth(Authority auth) {
        this.auth = auth;
    }

    public String getsha256hash(byte[] file_to_convert) throws NoSuchAlgorithmException, IOException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(file_to_convert);
        String sha256hex = new String(Hex.encode(hash));
        return sha256hex;
    }

    public String getRSAkeys(Integer size) throws NoSuchAlgorithmException, JSONException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(size);
        KeyPair key = keyGen.generateKeyPair();
        PrivateKey priv = key.getPrivate();
        PublicKey pub = key.getPublic();
        String privateKey = new String(Base64.encode(priv.getEncoded(), 0,priv.getEncoded().length));
        String publicKey= new String(Base64.encode(pub.getEncoded(), 0,pub.getEncoded().length));
        JSONObject my_obj = new JSONObject();


        my_obj.put("private key", privateKey);
        my_obj.put("public key", publicKey);


        String json_string = my_obj.toString();
        return json_string;
    }

}


