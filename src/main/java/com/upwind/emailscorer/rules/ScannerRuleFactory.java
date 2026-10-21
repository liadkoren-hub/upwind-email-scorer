package com.upwind.emailscorer.rules;

import com.upwind.emailscorer.service.CommunityReputationService;

import java.util.ArrayList;
import java.util.List;

/**
 * A factory class responsible for instantiating and providing the complete suite
 * of email scanning rules used by the service engine.
 *
 * @author Liad Koren
 */
public class ScannerRuleFactory {

	/**
	 * Creates and returns a list of all active email scanner rules.
	 *
	 * @param threatIntel The threat intelligence service required by specific rules.
	 * @return A list of instantiated rules to be executed on each email.
	 */
	public static List<EmailScannerRule> createAllRules(CommunityReputationService threatIntel) {
		List<EmailScannerRule> rules = new ArrayList<>();

		rules.add(new SenderIdentityRule(threatIntel));
		rules.add(new ContentAndUrgencyRule());
		rules.add(new AttachmentAnalysisRule());
		rules.add(new UrlAnalysisRule());

		return rules;
	}
}