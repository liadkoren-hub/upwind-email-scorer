
package com.upwind.emailscorer.controller;

import com.upwind.emailscorer.dto.*;
import com.upwind.emailscorer.service.CommunityReputationService;
import com.upwind.emailscorer.service.EmailScoringService;
import com.upwind.emailscorer.service.GoogleAuthenticationService;
import com.upwind.emailscorer.service.UserVerificationService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * The main REST controller for the email service API.
 * Handles incoming HTTP requests for email scanning, user verification,
 * and phishing reporting, delegating the logic to the appropriate services.
 * Authenticates incoming requests and validates user input.
 *
 * @author Liad Koren
 */
@RestController
@RequestMapping(ScanController.BASE_API_PATH)
public class ScanController {

	public static final String BASE_API_PATH = "/api";
	private static final String SCAN_ENDPOINT = "/scan";
	private static final String VERIFY_ENDPOINT = "/verify";
	private static final String VERIFY_STATUS_ENDPOINT = "/verification-status";
	private static final String REPORT_ENDPOINT = "/report";

	private static final String STATUS_NEW_JSON = "{\"status\": \"new\"}";
	private static final String STATUS_EXISTS_JSON = "{\"status\": \"exists\"}";
	private static final String STATUS_UNVERIFIED_JSON = "{\"status\": \"unverified\"}";
	private static final String STATUS_ERROR_JSON = "{\"status\": \"error\"}";

	private static final int MAX_SENDER_LENGTH = 500;
	private static final int MAX_SUBJECT_LENGTH = 1000;
	private static final int MAX_BODY_LENGTH = 100_000;
	private static final int MAX_ATTACHMENTS = 30;
	private static final int MAX_FILENAME_LENGTH = 255;

	private final EmailScoringService scoringService;
	private final CommunityReputationService threatIntelService;
	private final UserVerificationService userVerificationService;
	private final GoogleAuthenticationService googleAuthenticationService;

	/**
	 * Constructs the ScanController with its required service dependencies.
	 *
	 * @param scoringService              The service responsible for service emails.
	 * @param threatIntelService          The service managing sender reputation.
	 * @param userVerificationService     The service handling user verification state.
	 * @param googleAuthenticationService The service responsible for authenticating Google users.
	 */
	public ScanController(EmailScoringService scoringService,
						  CommunityReputationService threatIntelService,
						  UserVerificationService userVerificationService,
						  GoogleAuthenticationService googleAuthenticationService) {
		this.scoringService = scoringService;
		this.threatIntelService = threatIntelService;
		this.userVerificationService = userVerificationService;
		this.googleAuthenticationService = googleAuthenticationService;
	}

	/**
	 * Analyzes an email request and returns a scan response with a score and verdict.
	 * Only authenticated and fully verified users can scan emails.
	 *
	 * @param authorization The Google ID token provided in the Authorization header.
	 * @param request The email data to be scanned.
	 * @return A ScanResponse containing the results of the analysis.
	 */
	@PostMapping(SCAN_ENDPOINT)
	public ScanResponse scanEmail(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@RequestBody EmailRequest request) {

		String verifiedEmail = googleAuthenticationService.authenticate(authorization);

		if (!userVerificationService.isUserVerified(verifiedEmail)) {
			throw new ResponseStatusException(
					HttpStatus.FORBIDDEN, "Inbox verification required");
		}

		validateScanRequest(request);

		return scoringService.processEmail(request);
	}

	/**
	 * Processes a user verification request based on their inbox history.
	 * Uses the authenticated Google account instead of trusting the client-provided identity.
	 *
	 * @param authorization The Google ID token provided in the Authorization header.
	 * @param request The verification request data.
	 * @return A VerifyResponse indicating the verification progress or success.
	 */
	@PostMapping(VERIFY_ENDPOINT)
	public VerifyResponse verifyUser(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@RequestBody VerifyRequest request) {

		String verifiedEmail = googleAuthenticationService.authenticate(authorization);

		validateVerifyRequest(request);
		request.setUserEmail(verifiedEmail);

		return userVerificationService.processVerification(request);
	}

	/**
	 * Retrieves the current verification status and requirements of a user.
	 * Uses the authenticated Google identity to retrieve the correct state.
	 *
	 * @param authorization The Google ID token provided in the Authorization header.
	 * @return A VerifyResponse containing the current verification status and requirements.
	 */
	@GetMapping(VERIFY_STATUS_ENDPOINT)
	public VerifyResponse getVerificationStatus(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {

		String verifiedEmail = googleAuthenticationService.authenticate(authorization);

		return userVerificationService.getVerificationStatus(verifiedEmail);
	}

	/**
	 * Reports a sender as malicious. The report is only accepted if the user is verified.
	 * Uses the authenticated Google account as the reporter's identity.
	 *
	 * @param authorization The Google ID token provided in the Authorization header.
	 * @param request The report request containing the sender and reporter details.
	 * @return A JSON string representing the status of the report submission.
	 */
	@PostMapping(REPORT_ENDPOINT)
	public String reportEmail(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@RequestBody ReportRequest request) {

		String verifiedEmail = googleAuthenticationService.authenticate(authorization);

		validateReportRequest(request);
		request.setReporter(verifiedEmail);

		CommunityReputationService.ReportResultStatus status =
				threatIntelService.reportSender(request.getSender(), verifiedEmail);

		switch (status) {
			case NEW_SUCCESS:
				return STATUS_NEW_JSON;
			case ALREADY_EXISTS:
				return STATUS_EXISTS_JSON;
			case UNVERIFIED_ACCOUNT:
				return STATUS_UNVERIFIED_JSON;
			default:
				return STATUS_ERROR_JSON;
		}
	}

	/**
	 * Validates the incoming email scan request.
	 *
	 * @param request The email data to validate.
	 */
	private void validateScanRequest(EmailRequest request) {
		if (request == null) {
			throw badRequest("Missing scan request");
		}

		validateSender(request.getSender());

		if (request.getSubject() != null &&
				request.getSubject().length() > MAX_SUBJECT_LENGTH) {
			throw badRequest("Email subject is too long");
		}

		if (request.getBody() != null &&
				request.getBody().length() > MAX_BODY_LENGTH) {
			throw badRequest("Email body is too long");
		}

		if (request.getAttachmentNames() != null) {
			if (request.getAttachmentNames().size() > MAX_ATTACHMENTS) {
				throw badRequest("Too many attachments");
			}

			for (String filename : request.getAttachmentNames()) {
				if (filename == null || filename.isBlank() ||
						filename.length() > MAX_FILENAME_LENGTH) {
					throw badRequest("Invalid attachment filename");
				}
			}
		}
	}

	/**
	 * Validates the historical email metadata in a verification request.
	 *
	 * @param request The verification request to validate.
	 */
	private void validateVerifyRequest(VerifyRequest request) {
		if (request == null) {
			throw badRequest("Missing verification request");
		}

		validateSender(request.getEmailSender());

		if (request.getEmailDateMs() <= 0 ||
				request.getEmailDateMs() > System.currentTimeMillis()) {
			throw badRequest("Invalid email date");
		}
	}

	/**
	 * Validates the sender provided in a phishing report.
	 *
	 * @param request The report request to validate.
	 */
	private void validateReportRequest(ReportRequest request) {
		if (request == null) {
			throw badRequest("Missing report request");
		}

		validateSender(request.getSender());
	}

	/**
	 * Validates that a sender is present and within the allowed length.
	 *
	 * @param sender The sender string to validate.
	 */
	private void validateSender(String sender) {
		if (sender == null || sender.isBlank() ||
				sender.length() > MAX_SENDER_LENGTH) {
			throw badRequest("Invalid sender");
		}
	}

	/**
	 * Creates an HTTP 400 response for invalid input.
	 *
	 * @param message The validation error message.
	 * @return A ResponseStatusException representing a bad request.
	 */
	private ResponseStatusException badRequest(String message) {
		return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
	}
}
