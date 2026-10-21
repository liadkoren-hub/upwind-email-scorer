package com.upwind.emailscorer.service;

import com.upwind.emailscorer.dto.EmailRequest;
import com.upwind.emailscorer.dto.ScanResponse;
import com.upwind.emailscorer.rules.EmailScannerRule;
import com.upwind.emailscorer.rules.RuleResult;
import com.upwind.emailscorer.rules.ScannerRuleFactory;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;

/**
 * This service acts as the core service engine.
 * It retrieves all scanner rules, applies them to the incoming email request,
 * aggregates the penalty points, and determines the final verdict.
 *
 * @author Liad Koren
 */
@Service
public class EmailScoringService {

	private static final int MAX_SCORE = 100;
	private static final int SAFE_THRESHOLD = 20;
	private static final int SUSPICIOUS_THRESHOLD = 60;

	private static final String VERDICT_SAFE = "Safe";
	private static final String VERDICT_SUSPICIOUS = "Suspicious";
	private static final String VERDICT_MALICIOUS = "Malicious";

	private static final String NO_THREATS_MESSAGE = "לא נמצאו איומים. נראה בטוח.";

	private final CommunityReputationService threatIntel;

	/**
	 * Constructs the EmailScoringService with its required dependencies.
	 *
	 * @param threatIntel The threat intelligence service for checking sender reputation.
	 */
	public EmailScoringService(CommunityReputationService threatIntel) {
		this.threatIntel = threatIntel;
	}

	/**
	 * Processes an email request by applying all scanner rules and calculating a final score.
	 *
	 * @param request The incoming email data to be scanned.
	 * @return A ScanResponse containing the final score, verdict, and a list of reasons.
	 */
	public ScanResponse processEmail(EmailRequest request) {
		int totalScore = 0;
		List<String> allReasons = new ArrayList<>();

		List<EmailScannerRule> rules = ScannerRuleFactory.createAllRules(threatIntel);

		for (EmailScannerRule rule : rules) {
			RuleResult ruleResult = rule.analyze(request);
			totalScore += ruleResult.getPenaltyPoints();
			allReasons.addAll(ruleResult.getReasons());
		}

		if (totalScore > MAX_SCORE) {
			totalScore = MAX_SCORE;
		}

		String verdict = determineVerdict(totalScore);

		if (allReasons.isEmpty()) {
			allReasons.add(NO_THREATS_MESSAGE);
		}

		return new ScanResponse(totalScore, verdict, allReasons);
	}

	/**
	 * Determines the verdict based on the calculated total score.
	 *
	 * @param score The aggregated penalty points.
	 * @return A string representing the classification (Safe, Suspicious, or Malicious).
	 */
	private String determineVerdict(int score) {
		if (score <= SAFE_THRESHOLD) {
			return VERDICT_SAFE;
		} else if (score <= SUSPICIOUS_THRESHOLD) {
			return VERDICT_SUSPICIOUS;
		} else {
			return VERDICT_MALICIOUS;
		}
	}
}