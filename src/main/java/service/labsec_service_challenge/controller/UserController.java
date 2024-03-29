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
import service.labsec_service_challenge.repository.CertificateRepository;
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

@EnableConfigurationProperties({
        FileProp.class
})
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/user")
public class UserController {
    @Autowired
    private FileStorageService fp;

    @Autowired
    private AuthorityRepository ar;

    @Autowired
    private CryptographyRepository cr;

    @Autowired
    private UserRepository ur;

    @Autowired
    private CertificateRepository cer;

    @Autowired
    JwtUtils jwtUtils;


    @CrossOrigin
    @RequestMapping(value = "/new_dc", method = RequestMethod.POST)
    public String newDc(@RequestHeader("authorization") String jwt, @RequestBody SubjectRequest sr) throws IOException, JSONException, NoSuchAlgorithmException, CertificateParsingException, SignatureException, InvalidKeyException, CertificateEncodingException, InvalidKeySpecException {

        //verifica se existe AC ou se um certificado com esse nome já foi criado

        if (ar.count() == 0){
            return new MessageResponse("No AC available in system").getMessage();
        } else if (cer.findByName(sr.getCN()).isPresent()){
            return new MessageResponse("This cert name is already in use").getMessage();
        }
        //get authority data
        Authority a = ar.getById(sr.getAuth_id());

        //generate certification
        CertificateCA c = new CertificateCA();
        c.create_and_save_cert(sr, a);
        //store on database
        System.out.println(jwt.substring(7));
        String user_name = jwtUtils.getUserNameFromJwtToken(jwt.substring(7));
        Optional<User> user = ur.findByUsername(user_name);
        if (user.isPresent()){
            c.setName(sr.getCN());
            c.setValid(false);
            c.setIssuer(ar.getById(sr.getAuth_id()));
            c.setCert_owner(user.get());
            cer.save(c);
        }
        return new MessageResponse("Sucess").getMessage();
    }


    @CrossOrigin
    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(path = "/d_dc", method = RequestMethod.PUT)
    public String dactivate_dc(@RequestHeader("authorization") String jwt, @RequestBody Map<String, Object> json) throws IOException, JSONException {


        Long id = Long.valueOf((String) json.get("dc_id"));
        if (cer.existsById(id)){

            CertificateCA a = cer.getById(id);
            a.setValid(false);
            cer.save(a);
            return "{\"sucess\": true}";

        }


        return "{\"sucess\": false}";
    }


    @CrossOrigin
    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(path = "/a_dc", method = RequestMethod.PUT)
    public String activate_dc(@RequestHeader("authorization") String jwt, @RequestBody Map<String, Object> json) throws IOException, JSONException {


        Long id = Long.valueOf((String) json.get("dc_id"));
        if (cer.existsById(id)){

            CertificateCA a = cer.getById(id);
            a.setValid(true);
            cer.save(a);
            return "{\"sucess\": true}";

        }


        return "{\"sucess\": false}";
    }

    @CrossOrigin
    @RequestMapping(value = "/my_dcs", method = RequestMethod.GET)
    public String mydcs(@RequestHeader("authorization") String jwt) {
        JSONArray json = new JSONArray();
        String user_name = jwtUtils.getUserNameFromJwtToken(jwt.substring(7));
        Optional<User> user = ur.findByUsername(user_name);

        if (user.isPresent()){
            cer.findAllByCertowner(user.get()).forEach(certificateCA -> {


                try {
                    JSONObject jsonObj  = new JSONObject();
                    jsonObj.put("id", String.valueOf(certificateCA.getId()));
                    jsonObj.put("owner", certificateCA.getCert_owner().getUsername());
                    jsonObj.put("name", certificateCA.getName());
                    jsonObj.put("subject", certificateCA.getSubject());
                    jsonObj.put("valid", certificateCA.getValid());
                    json.put(jsonObj);
                } catch (JSONException e) {
                    e.printStackTrace();
                }

            });
        }

        return json.toString();
    }


    @CrossOrigin
    @RequestMapping(path = "/download", method = RequestMethod.POST)
    public String download(@RequestBody String name) throws IOException {
        if (cer.findByName(name).isPresent()){
            CertificateCA c = cer.findByName(name).get();
            if (c.getValid()){
                return c.getCertdata();


            } else {return "cant download";}
        }


        return "something went wrong";
    }


}

