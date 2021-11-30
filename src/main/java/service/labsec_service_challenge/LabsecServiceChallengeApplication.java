package service.labsec_service_challenge;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import service.labsec_service_challenge.entity.FileProp;

@SpringBootApplication

@EnableConfigurationProperties({
		FileProp.class
})
public class LabsecServiceChallengeApplication {

	public static void main(String[] args) {
		SpringApplication.run(LabsecServiceChallengeApplication.class, args);
	}

}
