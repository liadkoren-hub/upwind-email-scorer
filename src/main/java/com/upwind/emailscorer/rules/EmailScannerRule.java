package com.upwind.emailscorer.rules;

import com.upwind.emailscorer.dto.EmailRequest;

/**
 * Defines the contract for an email scanning rule within the service engine.
 * Implementing classes encapsulate specific security checks (e.g., attachment analysis,
 * content urgency, sender identity) and calculate penalty points accordingly.
 *
 * @author Liad Koren
 */
public interface EmailScannerRule {

	/**
	 * Analyzes the provided email request against the rule's specific criteria.
	 *
	 * @param request The incoming email request containing the email data to be analyzed.
	 * @return A RuleResult object containing any accumulated penalty points and the reasons for them.
	 */
	RuleResult analyze(EmailRequest request);
}