package com.upwind.emailscorer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The main entry point for the Email Scorer Spring Boot application.
 * Bootstraps the application context, initializes the embedded web server,
 * and starts the REST API backend.
 *
 * @author Liad Koren
 */
@SpringBootApplication
public class EmailScorerApplication {

	/**
	 * The main method that launches the Spring Boot application.
	 *
	 * @param args Command line arguments passed to the application.
	 */
	public static void main(String[] args) {
		SpringApplication.run(EmailScorerApplication.class, args);
	}

}