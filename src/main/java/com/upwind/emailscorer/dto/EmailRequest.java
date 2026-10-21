package com.upwind.emailscorer.dto;

import java.util.ArrayList;
import java.util.List;

/**
 * A Data Transfer Object (DTO) representing an incoming email scan request.
 * Contains the raw data extracted from the client side (e.g., Gmail Add-on)
 * required by the scanning engine to evaluate the email.
 *
 * @author Liad Koren
 */
public class EmailRequest {

	private String sender;
	private String subject;
	private String body;
	private List<String> attachmentNames;

	/**
	 * Default constructor. Initializes the attachment names list.
	 */
	public EmailRequest() {
		this.attachmentNames = new ArrayList<>();
	}

	/**
	 * Gets the sender of the email.
	 *
	 * @return The email address of the sender.
	 */
	public String getSender() {
		return sender;
	}

	/**
	 * Sets the sender of the email.
	 *
	 * @param sender The email address of the sender.
	 */
	public void setSender(String sender) {
		this.sender = sender;
	}

	/**
	 * Gets the subject of the email.
	 *
	 * @return The subject line.
	 */
	public String getSubject() {
		return subject;
	}

	/**
	 * Sets the subject of the email.
	 *
	 * @param subject The subject line.
	 */
	public void setSubject(String subject) {
		this.subject = subject;
	}

	/**
	 * Gets the plain text body of the email.
	 *
	 * @return The email body.
	 */
	public String getBody() {
		return body;
	}

	/**
	 * Sets the plain text body of the email.
	 *
	 * @param body The email body.
	 */
	public void setBody(String body) {
		this.body = body;
	}

	/**
	 * Gets the list of attachment names included in the email.
	 *
	 * @return A list of attachment filenames.
	 */
	public List<String> getAttachmentNames() {
		return attachmentNames;
	}

	/**
	 * Sets the list of attachment names.
	 *
	 * @param attachmentNames A list of attachment filenames.
	 */
	public void setAttachmentNames(List<String> attachmentNames) {
		this.attachmentNames = attachmentNames;
	}
}