package service.labsec_service_challenge.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import service.labsec_service_challenge.entity.Certificate;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> { }
