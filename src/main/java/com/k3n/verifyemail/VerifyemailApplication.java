package com.k3n.verifyemail;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class VerifyemailApplication {

	public static void main(String[] args) {
		SpringApplication.run(VerifyemailApplication.class, args);
	}

}