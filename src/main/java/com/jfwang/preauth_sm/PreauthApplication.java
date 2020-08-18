package com.jfwang.preauth_sm;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/*
 * demonstrate Spring Boot oauth2 + AAD with pre-authentication such as SiteMinder support
 */
@SpringBootApplication
public class PreauthApplication {

	public static void main(String[] args) {
		SpringApplication.run(PreauthApplication.class, args);
	}

}
