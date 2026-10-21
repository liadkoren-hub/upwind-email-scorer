
package com.upwind.emailscorer.dto;

/**
 * A Data Transfer Object (DTO) representing the user's verification status.
 * Contains the current verification status, progress, requirements,
 * and a message to be displayed to the user.
 *
 * @author Liad Koren
 */
public class VerifyResponse {

	private final boolean fullyVerified;
	private final int progress;
	private final String message;
	private final int requiredEmails;
	private final long minAgeDays;
	private final long minIntervalDays;

	/**
	 * Constructs a VerifyResponse with the specified verification outcome
	 * and requirements.
	 *
	 * @param fullyVerified   True if the user has completed verification.
	 * @param progress        The number of verified historical emails.
	 * @param message         A message describing the verification result.
	 * @param requiredEmails  The number of emails required for verification.
	 * @param minAgeDays      The minimum age of each email in days.
	 * @param minIntervalDays The minimum interval between emails in days.
	 */
	public VerifyResponse(boolean fullyVerified,
						  int progress,
						  String message,
						  int requiredEmails,
						  long minAgeDays,
						  long minIntervalDays) {
		this.fullyVerified = fullyVerified;
		this.progress = progress;
		this.message = message;
		this.requiredEmails = requiredEmails;
		this.minAgeDays = minAgeDays;
		this.minIntervalDays = minIntervalDays;
	}

	/**
	 * Checks if the user is fully verified and granted access.
	 *
	 * @return True if fully verified, false otherwise.
	 */
	public boolean isFullyVerified() {
		return fullyVerified;
	}

	/**
	 * Gets the current verification progress.
	 *
	 * @return The number of verified emails.
	 */
	public int getProgress() {
		return progress;
	}

	/**
	 * Gets the feedback message for the verification attempt.
	 *
	 * @return A message string.
	 */
	public String getMessage() {
		return message;
	}

	/**
	 * Gets the number of historical emails required for verification.
	 *
	 * @return The required number of emails.
	 */
	public int getRequiredEmails() {
		return requiredEmails;
	}

	/**
	 * Gets the minimum required age of historical emails.
	 *
	 * @return The minimum email age in days.
	 */
	public long getMinAgeDays() {
		return minAgeDays;
	}

	/**
	 * Gets the minimum required interval between historical emails.
	 *
	 * @return The minimum interval in days.
	 */
	public long getMinIntervalDays() {
		return minIntervalDays;
	}
}
