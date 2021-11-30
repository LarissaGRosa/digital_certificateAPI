package service.labsec_service_challenge.controller;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import service.labsec_service_challenge.entity.Cryptography;
import service.labsec_service_challenge.entity.Authority;
import service.labsec_service_challenge.entity.FileProp;
import service.labsec_service_challenge.entity.FileStorageService;
@EnableConfigurationProperties({
        FileProp.class
})
@RestController
public class StageController {
    @Autowired
    private FileStorageService fp;
    //Código que implementa a etapa 1
    @CrossOrigin
    @PostMapping("/hash_file")
    public String uploadFile(@RequestParam("file") MultipartFile file) throws Exception {
        Cryptography c = new Cryptography();
        byte[] bdata = FileCopyUtils.copyToByteArray(file.getInputStream());
        return c.getsha256hash(bdata);
    }

    //Código que implementa a etapa 2
    @CrossOrigin
    @RequestMapping(value = "/stage2", method =  RequestMethod.POST)
    public String RSA(@RequestBody Integer size) throws IOException, JSONException, NoSuchAlgorithmException {
        Cryptography c = new Cryptography();
        return c.getRSAkeys((int) size);
    }

    //Código que implementa a etapa 3 - certificado para AC-Raiz
    @CrossOrigin
    @RequestMapping(value = "/create_root_ca", method =  RequestMethod.POST)
    public String RootCa() throws IOException, JSONException, NoSuchAlgorithmException, CertificateParsingException, SignatureException, InvalidKeyException, CertificateEncodingException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair key = keyGen.generateKeyPair();
        PrivateKey priv = key.getPrivate();
        PublicKey pub = key.getPublic();
        Authority a = new Authority();
        Base64 encoder = new Base64();

        X509Certificate cert = a.makeCertificate(pub, 1,"CN=AC-RAIZ", "CN=AC-RAIZ", priv, new AlgorithmIdentifier(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())));
        byte[] derCert = cert.getEncoded();
        String pemCertPre = new String(encoder.encode(derCert));
        String pemCert = pemCertPre;
        File file = new File("src/main/resources/ac_raiz/ac.pem");
        File cert_pk = new File("src/main/resources/ac_raiz/ac_privk.pem");
        File cert_pubk = new File("src/main/resources/ac_raiz/ac_pubk.pem");
        try (OutputStream os = new FileOutputStream(file)) {
            os.write(pemCert.getBytes(StandardCharsets.UTF_8));
        }
        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                pub.getEncoded());
        FileOutputStream fos = new FileOutputStream(cert_pubk);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                priv.getEncoded());
        fos = new FileOutputStream(cert_pk);
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
        return cert.toString();
    }

    //Código que implementa a etapa 3 - certificado assinado por AC-Raiz
    @CrossOrigin
    @RequestMapping(value = "/create_new_ca", method =  RequestMethod.POST)
    public String newCas(@RequestBody String name) throws IOException, JSONException, NoSuchAlgorithmException, CertificateParsingException, SignatureException, InvalidKeyException, CertificateEncodingException, InvalidKeySpecException {

        File f = new File("src/main/resources/certificados_gerados/"+name+".pem");
        if (f.isFile() && f.canRead()) {
            return "Esse arquivo já existe";
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair key = keyGen.generateKeyPair();
        PrivateKey priv = key.getPrivate();
        PublicKey pub = key.getPublic();
        Authority a = new Authority();
        Base64 encoder = new Base64();
        File filePrivateKey = new File("src/main/resources/ac_raiz/ac_privk.pem");
        FileInputStream fis = new FileInputStream("src/main/resources/ac_raiz/ac_privk.pem");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        X509Certificate cert = a.makeCertificate(pub, name.hashCode(),"CN=AC-RAIZ", "CN="+name, privateKey, new AlgorithmIdentifier(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())));
        byte[] derCert = cert.getEncoded();
        String pemCertPre = new String(encoder.encode(derCert));
        String pemCert = pemCertPre;
        File file = new File("src/main/resources/certificados_gerados/"+name+".pem");
        File cert_pk = new File("src/main/resources/certificados_gerados/"+name+"_privk.pem");
        File cert_pubk = new File("src/main/resources/certificados_gerados/"+name+"_pubk.pem");
        try (OutputStream os = new FileOutputStream(file)) {
            os.write(pemCert.getBytes(StandardCharsets.UTF_8));
        }
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                pub.getEncoded());
        FileOutputStream fos = new FileOutputStream(cert_pubk);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                priv.getEncoded());
        fos = new FileOutputStream(cert_pk);
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();

        JSONObject jsonObj = new JSONObject();

        jsonObj.put("issuer", "CN=AC-RAIZ");
        jsonObj.put("subject", "CN="+name);
        jsonObj.put("serial_number", String.valueOf(name.hashCode()));
        return  jsonObj.toString();
    }
    @CrossOrigin
    @RequestMapping(path = "/download", method = RequestMethod.POST)
    public ResponseEntity<Resource> download(@RequestBody String name) throws IOException {
        File file = new File("src/main/resources/certificados_gerados/"+name+".pem");

        HttpHeaders header = new HttpHeaders();
        header.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename="+name+".pem");
        header.add("Cache-Control", "no-cache, no-store, must-revalidate");
        header.add("Pragma", "no-cache");
        header.add("Expires", "0");

        Path path = Paths.get(file.getAbsolutePath());
        ByteArrayResource resource = new ByteArrayResource(Files.readAllBytes(path));

        return ResponseEntity.ok()
                .headers(header)
                .contentLength(file.length())
                .contentType(MediaType.parseMediaType("application/octet-stream"))
                .body(resource);
    }


}
