
package com.upwind.emailscorer.rules;

import com.upwind.emailscorer.dto.EmailRequest;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class implements the content and urgency analysis rule.
 * It detects urgent language and requests for sensitive actions,
 * applying penalties based on individual and combined risk signals.
 *
 * @author Liad Koren
 */
public class ContentAndUrgencyRule implements EmailScannerRule {

	private static final int URGENCY_PENALTY = 15;
	private static final int SENSITIVE_ACTION_PENALTY = 30;
	private static final int COMBINED_RISK_PENALTY = 20;

	private static final String URGENCY_REASON_FORMAT =
			"ההודעה מכילה ניסוח שעלול להפעיל לחץ ('%s')";

	private static final String SENSITIVE_ACTION_REASON_FORMAT =
			"ההודעה מבקשת לבצע פעולה שקשורה למידע רגיש ('%s')";

	private static final String COMBINED_RISK_REASON =
			"שילוב של יצירת תחושת לחץ ובקשה לפעולה רגישה";

	private static final String EMPTY_STRING = "";
	private static final String SPACE_SEPARATOR = " ";

	// Matches urgency expressions in English and Hebrew.
	private static final Pattern URGENCY_PATTERN = Pattern.compile(
			"(?iu)(?<![\\p{L}\\p{N}])(?:"
					+ "urgent"
					+ "|immediate(?:ly)?"
					+ "|act\\s+now"
					+ "|within\\s+24\\s+hours"
					+ "|דחוף"
					+ "|מיידי"
					+ "|באופן\\s+מיידי"
					+ "|פעל\\s+עכשיו"
					+ ")(?![\\p{L}\\p{N}])"
	);

	// Matches requests for sensitive actions rather than isolated keywords.
	private static final Pattern SENSITIVE_ACTION_PATTERN = Pattern.compile(
			"(?iu)(?<![\\p{L}\\p{N}])(?:"
					+ "(?:enter|provide|submit|share)\\s+(?:your\\s+)?"
					+ "(?:password|verification\\s+code|one[-\\s]?time\\s+code"
					+ "|credit\\s+card\\s+(?:number|details)|card\\s+details)"
					+ "|(?:verify|confirm)\\s+(?:your\\s+)?(?:account|identity)"
					+ "|(?:update|confirm)\\s+(?:your\\s+)?"
					+ "(?:payment\\s+details|billing\\s+information)"
					+ "|(?:הזן|הזינו|מסור|מסרו|שלח|שלחו)\\s+(?:את\\s+)?"
					+ "(?:הסיסמה|סיסמה|קוד\\s+אימות|פרטי\\s+האשראי)"
					+ "|(?:אמת|אמתו|אשר|אשרו)\\s+(?:את\\s+)?"
					+ "(?:החשבון|הזהות)"
					+ "|(?:עדכן|עדכנו)\\s+(?:את\\s+)?פרטי\\s+התשלום"
					+ ")(?![\\p{L}\\p{N}])"
	);

	/**
	 * Analyzes the email content for urgency expressions and
	 * requests for sensitive actions.
	 * Applies an additional penalty when both signals are detected.
	 *
	 * @param request The incoming email request containing subject and body.
	 * @return A RuleResult containing penalty points and explanations.
	 */
	@Override
	public RuleResult analyze(EmailRequest request) {
		RuleResult result = new RuleResult();

		String subject = request.getSubject() != null
				? request.getSubject() : EMPTY_STRING;

		String body = request.getBody() != null
				? request.getBody() : EMPTY_STRING;

		String combinedText = subject + SPACE_SEPARATOR + body;

		Matcher urgencyMatcher = URGENCY_PATTERN.matcher(combinedText);
		Matcher sensitiveMatcher = SENSITIVE_ACTION_PATTERN.matcher(combinedText);

		boolean foundUrgency = urgencyMatcher.find();
		boolean foundSensitiveAction = sensitiveMatcher.find();

		if (foundUrgency) {
			String reason = String.format(
					URGENCY_REASON_FORMAT, urgencyMatcher.group());

			result.addPenalty(URGENCY_PENALTY, reason);
		}

		if (foundSensitiveAction) {
			String reason = String.format(
					SENSITIVE_ACTION_REASON_FORMAT, sensitiveMatcher.group());

			result.addPenalty(SENSITIVE_ACTION_PENALTY, reason);
		}

		if (foundUrgency && foundSensitiveAction) {
			result.addPenalty(
					COMBINED_RISK_PENALTY, COMBINED_RISK_REASON);
		}

		return result;
	}
}
