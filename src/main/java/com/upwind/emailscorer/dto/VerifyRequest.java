package com.upwind.emailscorer.dto;

/**
 * A Data Transfer Object (DTO) representing a user verification request.
 * Contains the user's email address and the metadata of the historical email
 * being submitted for the "Proof of Inbox History" challenge.
 *
 * @author Liad Koren
 */
public class VerifyRequest {

	private String userEmail;
	private String emailSender;
	private long emailDateMs;

	/**
	 * Gets the email address of the user requesting verification.
	 *
	 * @return The user's email address.
	 */
	public String getUserEmail() {
		return userEmail;
	}

	/**
	 * Sets the email address of the user requesting verification.
	 *
	 * @param userEmail The user's email address.
	 */
	public void setUserEmail(String userEmail) {
		this.userEmail = userEmail;
	}

	/**
	 * Gets the sender of the historical email being submitted.
	 *
	 * @return The sender's email address.
	 */
	public String getEmailSender() {
		return emailSender;
	}

	/**
	 * Sets the sender of the historical email being submitted.
	 *
	 * @param emailSender The sender's email address.
	 */
	public void setEmailSender(String emailSender) {
		this.emailSender = emailSender;
	}

	/**
	 * Gets the timestamp of the historical email being submitted.
	 *
	 * @return The email receipt date in milliseconds since the epoch.
	 */
	public long getEmailDateMs() {
		return emailDateMs;
	}

	/**
	 * Sets the timestamp of the historical email being submitted.
	 *
	 * @param emailDateMs The email receipt date in milliseconds since the epoch.
	 */
	public void setEmailDateMs(long emailDateMs) {
		this.emailDateMs = emailDateMs;
	}
}