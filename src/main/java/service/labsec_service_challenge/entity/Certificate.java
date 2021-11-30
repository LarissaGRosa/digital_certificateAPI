package service.labsec_service_challenge.entity;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class Certificate
{
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @Column(nullable = false)
    private String issuer;

    @Column(nullable = false)
    private String serial_number;

    @Column(nullable = false)
    private String subject;

    public long getId() {
        return id;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSerial_number(){return serial_number;}

    public String getSubject(){return subject;}

    public void setIssuer(String nome) {
        this.issuer = nome;
    }

    public void setId(long id) {
        this.id = id;
    }

    public void setSerial_number(String serial_number) {this.serial_number = serial_number;}

    public void setSubject(String subject){this.subject = subject;}
}

