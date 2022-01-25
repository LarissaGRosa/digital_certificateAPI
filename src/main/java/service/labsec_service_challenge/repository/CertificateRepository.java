package service.labsec_service_challenge.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import service.labsec_service_challenge.entity.Authority;
import service.labsec_service_challenge.entity.CertificateCA;
import service.labsec_service_challenge.entity.User;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<CertificateCA, Long> {
    Optional<CertificateCA> findByName(String name);
    List<CertificateCA> findAllByCertowner(User owner);
}
