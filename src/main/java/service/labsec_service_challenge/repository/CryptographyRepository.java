package service.labsec_service_challenge.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import service.labsec_service_challenge.entity.*;


@Repository
public interface CryptographyRepository extends JpaRepository<Cryptography, Long> {

}