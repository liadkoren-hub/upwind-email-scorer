
package com.upwind.emailscorer.service;

import org.springframework.stereotype.Service;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages threat intelligence and sender reputation.
 * Tracks unique phishing reports per sender and determines if a sender
 * should be blacklisted based on community feedback.
 * Ensures that only fully verified users can submit reports.
 *
 * @author Liad Koren
 */
@Service
public class CommunityReputationService {

	private static final int BLACKLIST_THRESHOLD = 3;
	private static final int ZERO_REPORTS = 0;

	private final ConcurrentHashMap<String, Set<String>> reportedSenders;
	private final UserVerificationService userVerificationService;

	/**
	 * Defines the possible outcomes when a user attempts to report a sender.
	 */
	public enum ReportResultStatus {
		/**
		 * A new report was successfully received and verified.
		 */
		NEW_SUCCESS,
		/**
		 * The user has already reported this sender, or the input was invalid.
		 */
		ALREADY_EXISTS,
		/**
		 * The report was rejected because the user has not completed verification.
		 */
		UNVERIFIED_ACCOUNT
	}

	/**
	 * Constructs the CommunityReputationService with its required dependencies.
	 *
	 * @param userVerificationService The service that manages user verification states.
	 */
	public CommunityReputationService(UserVerificationService userVerificationService) {
		this.userVerificationService = userVerificationService;
		this.reportedSenders = new ConcurrentHashMap<>();
	}

	/**
	 * Processes a report against a specific sender from a given reporter.
	 * Validates the reporter's verification status before accepting the report.
	 *
	 * @param sender        The email address of the suspicious sender.
	 * @param reporterEmail The email address of the user submitting the report.
	 * @return The status of the report submission.
	 */
	public ReportResultStatus reportSender(String sender, String reporterEmail) {
		String normalizedSender = normalizeSender(sender);

		if (normalizedSender.isEmpty() ||
				reporterEmail == null || reporterEmail.isBlank()) {
			return ReportResultStatus.ALREADY_EXISTS;
		}

		String normalizedReporter = reporterEmail.toLowerCase(Locale.ROOT).trim();

		boolean isVerified = userVerificationService.isUserVerified(normalizedReporter);
		if (!isVerified) {
			return ReportResultStatus.UNVERIFIED_ACCOUNT;
		}

		Set<String> reporters = reportedSenders.get(normalizedSender);
		if (reporters == null) {
			Set<String> newReportersSet = ConcurrentHashMap.newKeySet();
			Set<String> existingSet = reportedSenders.putIfAbsent(normalizedSender, newReportersSet);

			if (existingSet != null) {
				reporters = existingSet;
			} else {
				reporters = newReportersSet;
			}
		}

		boolean isNew = reporters.add(normalizedReporter);

		if (isNew) {
			return ReportResultStatus.NEW_SUCCESS;
		} else {
			return ReportResultStatus.ALREADY_EXISTS;
		}
	}

	/**
	 * Retrieves the number of unique reports submitted against a specific sender.
	 *
	 * @param sender The sender's email address.
	 * @return The total number of unique reports, or zero if none exist.
	 */
	public int getReportCount(String sender) {
		String normalizedSender = normalizeSender(sender);

		if (normalizedSender.isEmpty()) {
			return ZERO_REPORTS;
		}

		Set<String> reporters = reportedSenders.get(normalizedSender);
		return reporters != null ? reporters.size() : ZERO_REPORTS;
	}

	/**
	 * Checks if a sender has reached or exceeded the required report threshold for blacklisting.
	 *
	 * @param sender The sender's email address.
	 * @return True if the sender is blacklisted, false otherwise.
	 */
	public boolean isBlacklisted(String sender) {
		return getReportCount(sender) >= BLACKLIST_THRESHOLD;
	}

	/**
	 * Extracts and normalizes the sender's email address.
	 * Removes the display name and converts the address to lowercase.
	 *
	 * @param sender The full sender string.
	 * @return The normalized email address, or an empty string if missing.
	 */
	private String normalizeSender(String sender) {
		if (sender == null || sender.isBlank()) {
			return "";
		}

		String address = sender.trim();

		int openBracket = address.lastIndexOf('<');
		int closeBracket = address.lastIndexOf('>');

		if (openBracket >= 0 && closeBracket > openBracket) {
			address = address.substring(openBracket + 1, closeBracket).trim();
		}

		return address.toLowerCase(Locale.ROOT);
	}
}
