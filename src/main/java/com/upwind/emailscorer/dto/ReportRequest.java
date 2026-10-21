package com.upwind.emailscorer.dto;

/**
 * A Data Transfer Object (DTO) representing a request to report a sender as malicious.
 * Contains the email address of the suspicious sender and the email address of the user reporting it.
 *
 * @author Liad Koren
 */
public class ReportRequest {

	private String sender;
	private String reporter;

	/**
	 * Gets the email address of the reported sender.
	 *
	 * @return The reported sender's email address.
	 */
	public String getSender() {
		return sender;
	}

	/**
	 * Sets the email address of the reported sender.
	 *
	 * @param sender The reported sender's email address.
	 */
	public void setSender(String sender) {
		this.sender = sender;
	}

	/**
	 * Gets the email address of the user who is reporting the sender.
	 *
	 * @return The reporter's email address.
	 */
	public String getReporter() {
		return reporter;
	}

	/**
	 * Sets the email address of the user who is reporting the sender.
	 *
	 * @param reporter The reporter's email address.
	 */
	public void setReporter(String reporter) {
		this.reporter = reporter;
	}
}