package service.labsec_service_challenge.entity;
import javax.persistence.*;

@Entity
@Table(name = "UserType")
public class UserType {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private UserEnum name;

    public UserType() {

    }

    public UserType(UserEnum name) {
        this.name = name;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public UserEnum getName() {
        return name;
    }

    public void setName(UserEnum name) {
        this.name = name;
    }
}
