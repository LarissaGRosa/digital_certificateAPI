package service.labsec_service_challenge.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import service.labsec_service_challenge.entity.Authority;
import service.labsec_service_challenge.entity.User;
import service.labsec_service_challenge.entity.UserEnum;
import service.labsec_service_challenge.entity.UserType;


@Repository
public interface AuthorityRepository extends JpaRepository<Authority, Long> {
    Optional<Authority> findByOwner(User user);
    Optional<Authority> findByName(String name);

}