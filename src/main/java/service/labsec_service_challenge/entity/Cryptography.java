package service.labsec_service_challenge.entity;
import org.json.JSONException;
import org.json.JSONObject;
import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.bouncycastle.*;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.data.util.Pair;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;


/**
 * Classe responsável por executar a etapa 1
 */
public class Cryptography {


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


