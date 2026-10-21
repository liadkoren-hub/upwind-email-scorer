
package com.upwind.emailscorer.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Locale;

/**
 * Service responsible for authenticating users through Google ID tokens.
 * Verifies the token's validity and intended OAuth client audience,
 * and ensures that the associated Google account has a verified email address.
 * Returns the authenticated user's email address to prevent identity spoofing
 * through client-supplied user information.
 *
 * @author Liad Koren
 */
@Service
public class GoogleAuthenticationService {

	private static final String AUTHORIZATION_PREFIX = "Bearer ";

	private static final String ERROR_MISSING_CLIENT_ID =
			"Google OAuth client ID is missing";

	private static final String ERROR_INVALID_TOKEN =
			"Missing or invalid Google ID token";

	private static final String ERROR_VERIFICATION_UNAVAILABLE =
			"Unable to verify Google identity right now";

	private final GoogleIdTokenVerifier verifier;

	/**
	 * Constructs the GoogleAuthenticationService and initializes the Google
	 * ID token verifier with the application's configured OAuth client ID.
	 *
	 * @param clientId The Google OAuth client ID used to verify the token's audience.
	 * @throws IllegalArgumentException If the client ID is missing or blank.
	 */
	public GoogleAuthenticationService(
			@Value("${auth.google.client-id}") String clientId) {

		if (clientId == null || clientId.isBlank()) {
			throw new IllegalArgumentException(ERROR_MISSING_CLIENT_ID);
		}

		this.verifier = new GoogleIdTokenVerifier.Builder(
				new NetHttpTransport(),
				GsonFactory.getDefaultInstance())
				.setAudience(List.of(clientId))
				.build();
	}

	/**
	 * Authenticates an incoming request using a Google ID token.
	 * Validates the Authorization header, verifies the token against Google,
	 * and checks that the associated email address has been verified.
	 * Uses the verified token payload instead of trusting client-supplied identity data.
	 *
	 * @param authorizationHeader The HTTP Authorization header containing a Bearer token.
	 * @return The authenticated Google account's normalized email address.
	 * @throws ResponseStatusException If the token is missing, invalid,
	 *                                 or cannot currently be verified.
	 */
	public String authenticate(String authorizationHeader) {

		if (authorizationHeader == null ||
				!authorizationHeader.startsWith(AUTHORIZATION_PREFIX)) {
			throw unauthorized();
		}

		String token = authorizationHeader
				.substring(AUTHORIZATION_PREFIX.length())
				.trim();

		if (token.isEmpty()) {
			throw unauthorized();
		}

		final GoogleIdToken idToken;

		try {
			idToken = verifier.verify(token);

		} catch (GeneralSecurityException | IllegalArgumentException ex) {
			throw unauthorized();

		} catch (IOException ex) {
			throw new ResponseStatusException(
					HttpStatus.SERVICE_UNAVAILABLE,
					ERROR_VERIFICATION_UNAVAILABLE);
		}

		if (idToken == null ||
				!Boolean.TRUE.equals(idToken.getPayload().getEmailVerified())) {
			throw unauthorized();
		}

		String email = idToken.getPayload().getEmail();

		if (email == null || email.isBlank() ||
				idToken.getPayload().getSubject() == null) {
			throw unauthorized();
		}

		return email.trim().toLowerCase(Locale.ROOT);
	}

	/**
	 * Creates an HTTP 401 Unauthorized exception for missing or invalid
	 * Google authentication credentials.
	 *
	 * @return A ResponseStatusException indicating unauthorized access.
	 */
	private ResponseStatusException unauthorized() {
		return new ResponseStatusException(
				HttpStatus.UNAUTHORIZED,
				ERROR_INVALID_TOKEN);
	}
}
