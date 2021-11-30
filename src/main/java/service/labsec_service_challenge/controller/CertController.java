package service.labsec_service_challenge.controller;


import java.util.List;
import java.util.Optional;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import service.labsec_service_challenge.entity.Certificate;
import service.labsec_service_challenge.repository.CertificateRepository;

@RestController
public class CertController {
    @Autowired
    private CertificateRepository _Repository;
    @CrossOrigin
    @RequestMapping(value = "/certs", method = RequestMethod.GET)
    public List<Certificate> Get() {
        return _Repository.findAll();
    }
    @CrossOrigin
    @RequestMapping(value = "/save_cert", method =  RequestMethod.POST)
    public Certificate Post( @RequestBody Certificate c)
    {
        return _Repository.save(c);
    }


}
