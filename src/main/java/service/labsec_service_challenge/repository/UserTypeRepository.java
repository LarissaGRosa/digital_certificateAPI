package service.labsec_service_challenge.repository;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import service.labsec_service_challenge.entity.UserEnum;
import service.labsec_service_challenge.entity.UserType;


@Repository
public interface UserTypeRepository extends JpaRepository<UserType, Long> {
    Optional<UserType> findByName(UserEnum name);
}