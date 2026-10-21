
package com.upwind.emailscorer.rules;

import com.upwind.emailscorer.dto.EmailRequest;
import com.upwind.emailscorer.service.CommunityReputationService;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * This class implements the sender identity analysis rule.
 * It evaluates the sender's domain, detects brand and authority
 * impersonation, and consults the threat intelligence service.
 * Domain recognition is heuristic and does not authenticate
 * the sender using SPF, DKIM, or DMARC.
 *
 * @author Liad Koren
 */
public class SenderIdentityRule implements EmailScannerRule {

	private static final Set<String> FREE_PROVIDERS = Set.of(
			"gmail.com", "yahoo.com", "hotmail.com",
			"outlook.com", "protonmail.com"
	);

	private static final Set<String> TRUSTED_DOMAINS = Set.of(
			"savion.huji.ac.il", "huji.ac.il",
			"upwind.io", "github.com", "google.com"
	);

	private static final Map<String, String> BRAND_DOMAINS = Map.of(
			"google", "google.com",
			"paypal", "paypal.com",
			"apple", "apple.com",
			"microsoft", "microsoft.com",
			"amazon", "amazon.com"
	);

	private static final Set<String> AUTHORITY_ROLES = Set.of(
			"admin", "support", "security"
	);

	private static final int BLACKLIST_PENALTY = 60;
	private static final int SUSPICIOUS_REPORTS_PENALTY = 15;
	private static final int FREE_PROVIDER_PENALTY = 5;
	private static final int UNKNOWN_DOMAIN_PENALTY = 5;
	private static final int BRAND_IMPERSONATION_PENALTY = 50;
	private static final int AUTHORITY_IMPERSONATION_PENALTY = 30;

	private static final String BLACKLIST_REASON_FORMAT =
			"השולח צבר מספר משמעותי של דיווחי פישינג מהקהילה (%d דיווחים)";

	private static final String SUSPICIOUS_REPORTS_REASON =
			"התקבל דיווח פישינג על שולח זה מקהילת המשתמשים";

	private static final String FREE_PROVIDER_REASON_FORMAT =
			"כתובת השולח שייכת לספק אימייל חינמי (%s)";

	private static final String UNKNOWN_DOMAIN_REASON_FORMAT =
			"דומיין השולח אינו מופיע ברשימת הדומיינים המוכרים (%s)";

	private static final String BRAND_IMPERSONATION_REASON_FORMAT =
			"חשד להתחזות למותג '%s': דומיין השולח אינו תואם למותג (%s)";

	private static final String AUTHORITY_IMPERSONATION_REASON_FORMAT =
			"חשד להתחזות לגורם סמכותי: '%s' משתמש בכתובת אימייל חינמית (%s)";

	private static final char AT_SYMBOL = '@';
	private static final char OPEN_BRACKET = '<';
	private static final char CLOSE_BRACKET = '>';

	private static final String WORD_DELIMITER_REGEX = "(?U)\\W+";
	private static final String EMPTY_STRING = "";

	private static final int NOT_FOUND = -1;
	private static final int INDEX_OFFSET = 1;

	private final CommunityReputationService threatIntel;

	/**
	 * Constructs the SenderIdentityRule with the required threat intelligence dependency.
	 *
	 * @param threatIntel The service used to check sender reputation.
	 */
	public SenderIdentityRule(CommunityReputationService threatIntel) {
		this.threatIntel = threatIntel;
	}

	/**
	 * Analyzes the sender's domain, display name, and community reputation.
	 * Detects potential brand impersonation and authority impersonation
	 * while reducing penalties for common legitimate sender patterns.
	 *
	 * @param request The incoming email request containing sender information.
	 * @return A RuleResult containing penalty points and explanations.
	 */
	@Override
	public RuleResult analyze(EmailRequest request) {
		RuleResult result = new RuleResult();
		String fullSender = request.getSender();

		if (fullSender == null || fullSender.isBlank()) {
			return result;
		}

		// Check community reports.
		int reportCount = threatIntel.getReportCount(fullSender);

		if (threatIntel.isBlacklisted(fullSender)) {
			String reason = String.format(BLACKLIST_REASON_FORMAT, reportCount);
			result.addPenalty(BLACKLIST_PENALTY, reason);

		} else if (reportCount > 0) {
			result.addPenalty(
					SUSPICIOUS_REPORTS_PENALTY,
					SUSPICIOUS_REPORTS_REASON
			);
		}

		// Extract the sender's email address and display name.
		String emailAddress = extractEmailAddress(fullSender);
		String domain = extractDomain(emailAddress);
		String displayName = extractDisplayName(fullSender)
				.toLowerCase(Locale.ROOT);

		if (domain.isEmpty()) {
			return result;
		}

		boolean isFreeProvider = FREE_PROVIDERS.contains(domain);
		boolean isKnown = isKnownDomain(domain);

		// Evaluate the sender's domain.
		if (isFreeProvider) {
			String reason = String.format(
					FREE_PROVIDER_REASON_FORMAT, domain);

			result.addPenalty(FREE_PROVIDER_PENALTY, reason);

		} else if (!isKnown) {
			String reason = String.format(
					UNKNOWN_DOMAIN_REASON_FORMAT, domain);

			result.addPenalty(UNKNOWN_DOMAIN_PENALTY, reason);
		}

		if (displayName.isEmpty()) {
			return result;
		}

		String[] nameTokens = displayName.split(WORD_DELIMITER_REGEX);

		// Detect brand impersonation.
		boolean brandImpersonationDetected = false;

		for (String word : nameTokens) {
			if (BRAND_DOMAINS.containsKey(word)) {
				String expectedDomain = BRAND_DOMAINS.get(word);

				if (!matchesDomain(domain, expectedDomain)) {
					String reason = String.format(
							BRAND_IMPERSONATION_REASON_FORMAT, word, domain);

					result.addPenalty(BRAND_IMPERSONATION_PENALTY, reason);
					brandImpersonationDetected = true;
					break;
				}
			}
		}

		// Detect authority impersonation using free email providers.
		// Avoid applying two impersonation penalties for the same sender.
		if (isFreeProvider && !brandImpersonationDetected) {
			for (String word : nameTokens) {
				if (AUTHORITY_ROLES.contains(word)) {
					String reason = String.format(
							AUTHORITY_IMPERSONATION_REASON_FORMAT, word, domain);

					result.addPenalty(AUTHORITY_IMPERSONATION_PENALTY, reason);
					break;
				}
			}
		}

		return result;
	}

	/**
	 * Checks whether a domain matches an expected domain or one of its subdomains.
	 *
	 * @param domain The actual sender domain.
	 * @param expectedDomain The expected domain.
	 * @return True if the domain matches or is a subdomain.
	 */
	private boolean matchesDomain(String domain, String expectedDomain) {
		return domain.equals(expectedDomain) ||
				domain.endsWith("." + expectedDomain);
	}

	/**
	 * Checks whether the sender's domain is recognized.
	 * Includes configured trusted domains and known brand domains.
	 * Recognition does not prove that the sender is authenticated.
	 *
	 * @param domain The sender's domain.
	 * @return True if the domain is recognized.
	 */
	private boolean isKnownDomain(String domain) {
		for (String trustedDomain : TRUSTED_DOMAINS) {
			if (matchesDomain(domain, trustedDomain)) {
				return true;
			}
		}

		for (String brandDomain : BRAND_DOMAINS.values()) {
			if (matchesDomain(domain, brandDomain)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Extracts the email address from a full sender string.
	 * Supports both plain email addresses and display-name formats.
	 *
	 * @param sender The full sender string (e.g., "Name <user@domain.com>").
	 * @return The extracted email address in lowercase.
	 */
	private String extractEmailAddress(String sender) {
		int openBracketIndex = sender.lastIndexOf(OPEN_BRACKET);

		if (openBracketIndex != NOT_FOUND) {
			int closeBracketIndex = sender.indexOf(
					CLOSE_BRACKET, openBracketIndex);

			if (closeBracketIndex > openBracketIndex) {
				return sender.substring(
						openBracketIndex + INDEX_OFFSET,
						closeBracketIndex
				).trim().toLowerCase(Locale.ROOT);
			}
		}

		return sender.trim().toLowerCase(Locale.ROOT);
	}

	/**
	 * Extracts the domain from an email address.
	 *
	 * @param emailAddress The sender's email address.
	 * @return The domain in lowercase, or an empty string if unavailable.
	 */
	private String extractDomain(String emailAddress) {
		int atIndex = emailAddress.lastIndexOf(AT_SYMBOL);

		if (atIndex == NOT_FOUND ||
				atIndex == emailAddress.length() - INDEX_OFFSET) {
			return EMPTY_STRING;
		}

		return emailAddress.substring(atIndex + INDEX_OFFSET)
				.trim().toLowerCase(Locale.ROOT);
	}

	/**
	 * Extracts the display name from a full sender string.
	 *
	 * @param sender The full sender string (e.g., "Name <user@domain.com>").
	 * @return The display name, or an empty string if none exists.
	 */
	private String extractDisplayName(String sender) {
		int openBracketIndex = sender.indexOf(OPEN_BRACKET);

		if (openBracketIndex > 0) {
			return sender.substring(0, openBracketIndex).trim();
		}

		return EMPTY_STRING;
	}
}
