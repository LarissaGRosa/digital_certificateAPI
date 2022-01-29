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
import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.json.JSONArray;
import service.labsec_service_challenge.entity.CertificateCA;
import service.labsec_service_challenge.payloads.MessageResponse;
import service.labsec_service_challenge.security.JwtUtils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x500.X500Name;
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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import service.labsec_service_challenge.entity.*;
import service.labsec_service_challenge.payloads.LoginRequest;
import service.labsec_service_challenge.payloads.SubjectRequest;
import service.labsec_service_challenge.repository.AuthorityRepository;
import service.labsec_service_challenge.repository.CryptographyRepository;
import service.labsec_service_challenge.repository.UserRepository;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;
@EnableConfigurationProperties({
        FileProp.class
})
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/adm")
public class AdmController {
    @Autowired
    private FileStorageService fp;

    @Autowired
    private AuthorityRepository ar;

    @Autowired
    private CryptographyRepository cr;

    @Autowired
    private UserRepository ur;

    @Autowired
    JwtUtils jwtUtils;


    @CrossOrigin
    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(value = "/new_ac", method = RequestMethod.POST)
    public String newCa(@RequestHeader("authorization") String jwt, @RequestBody SubjectRequest sr) throws IOException, JSONException, NoSuchAlgorithmException, CertificateParsingException, SignatureException, InvalidKeyException, CertificateEncodingException {
        if (ar.findByName(sr.getCN()).isPresent()){
            return new MessageResponse("This ac name is already in use").toString();
        }
        Authority a = new Authority();
        a.create_and_save_cert(sr);
        String user_name = jwtUtils.getUserNameFromJwtToken(jwt.substring(7));
        Optional<User> user = ur.findByUsername(user_name);
        if (user.isPresent()){
            a.setName(sr.getCN());
            a.setValid(true);
            a.setCrypto(cr.saveAndFlush(a.getCrypto()));
            a.setOwner(user.get());
            ar.save(a);
        }
        return a.getCertdata();
    }


    @CrossOrigin
    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(path = "/d_ac", method = RequestMethod.PUT)
    public String deactivate_ac(@RequestHeader("Authorization") String jwt, @RequestBody Map<String, Object> json) throws IOException, JSONException {

        String user_name = jwtUtils.getUserNameFromJwtToken(jwt.substring(7));
        Optional<User> user = ur.findByUsername(user_name);
        Long id = Long.valueOf((String) json.get("ac_id"));
        if (ar.existsById(id)){

            Authority a = ar.getById(id);
            if (user.isPresent()){
                if (user.get().getId() == a.getOwner().getId()){
                    a.setValid(false);
                    ar.save(a);
                    return "{\"sucess\": true}";
                }}

        }


        return "{\"sucess\": false}";
    }


    @CrossOrigin
    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(path = "/a_ac", method = RequestMethod.PUT)
    public String activate_ac(@RequestHeader("authorization") String jwt, @RequestBody Map<String, Object> json) throws IOException, JSONException {

        String user_name = jwtUtils.getUserNameFromJwtToken(jwt.substring(7));
        Optional<User> user = ur.findByUsername(user_name);
        Long id = Long.valueOf((String) json.get("ac_id"));
        if (ar.existsById(id)){

            Authority a = ar.getById(id);
            if (user.isPresent()){
                if (user.get().getId() == a.getOwner().getId()){
                    a.setValid(true);
                    ar.save(a);
                    return "{\"sucess\": true}";
                }}

        }


        return "{\"sucess\": false}";
    }

    @CrossOrigin
    @RequestMapping(value = "/all_acs", method = RequestMethod.GET)
    public String  Allacs() {
        JSONArray json = new JSONArray();
        ar.findAll().forEach(authority -> {


            try {
                JSONObject jsonObj  = new JSONObject();
                jsonObj.put("id", String.valueOf(authority.getId()));
                jsonObj.put("owner", authority.getOwner().getUsername());
                jsonObj.put("name", authority.getName());
                jsonObj.put("subject", authority.getSubject());
                jsonObj.put("valid", authority.getValid());
                json.put(jsonObj);
            } catch (JSONException e) {
                e.printStackTrace();
            }

        });
        return json.toString();
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
