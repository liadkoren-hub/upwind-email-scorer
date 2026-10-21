
package com.upwind.emailscorer.rules;

import com.upwind.emailscorer.dto.EmailRequest;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class implements the URL analysis rule.
 * It detects suspicious URL structures, including brand impersonation,
 * direct IP addresses, shortened URLs, and unencrypted HTTP links.
 * Applies a penalty based on the highest detected risk level.
 * Does not open or visit the URLs.
 *
 * @author Liad Koren
 */
public class UrlAnalysisRule implements EmailScannerRule {

	private static final Pattern URL_PATTERN = Pattern.compile(
			"https?://[^\\s<>\"']+",
			Pattern.CASE_INSENSITIVE
	);

	private static final Pattern IPV4_PATTERN = Pattern.compile(
			"^(?:\\d{1,3}\\.){3}\\d{1,3}$"
	);

	private static final Set<String> BRAND_DOMAINS = Set.of(
			"paypal.com", "google.com", "microsoft.com", "amazon.com"
	);

	private static final Set<String> URL_SHORTENERS = Set.of(
			"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly"
	);

	private static final int BRAND_IMPERSONATION_PENALTY = 35;
	private static final int IP_ADDRESS_PENALTY = 20;
	private static final int SHORTENED_URL_PENALTY = 10;
	private static final int HTTP_PENALTY = 5;
	private static final int NO_PENALTY = 0;

	private static final int NOT_FOUND = -1;

	private static final String HTTP_SCHEME = "http";

	private static final String BRAND_REASON_FORMAT =
			"זוהה קישור עם דומיין שעלול להתחזות למותג מוכר (%s)";

	private static final String IP_REASON_FORMAT =
			"זוהה קישור המשתמש בכתובת IP במקום בשם דומיין (%s)";

	private static final String SHORTENER_REASON_FORMAT =
			"זוהה קישור מקוצר שמסתיר את כתובת היעד (%s)";

	private static final String HTTP_REASON_FORMAT =
			"זוהה קישור המשתמש ב-HTTP ללא הצפנה (%s)";

	private static final String NO_STRUCTURAL_RISK_REASON_FORMAT =
			"זוהה קישור לדומיין %s ללא אינדיקציות סיכון במבנה כתובת ה-URL";

	private static final String TRAILING_PUNCTUATION = ".,;!?)]}";

	/**
	 * Analyzes URLs appearing in the email subject and body.
	 * Records suspicious links while applying only the highest penalty.
	 *
	 * @param request The incoming email request containing subject and body.
	 * @return A RuleResult containing penalty points and explanations.
	 */
	@Override
	public RuleResult analyze(EmailRequest request) {
		RuleResult result = new RuleResult();

		String subject = request.getSubject() == null
				? "" : request.getSubject();

		String body = request.getBody() == null
				? "" : request.getBody();

		String text = subject + " " + body;
		Matcher matcher = URL_PATTERN.matcher(text);

		List<String> reasons = new ArrayList<>();
		int highestPenalty = NO_PENALTY;
		int highestRiskIndex = NOT_FOUND;

		while (matcher.find()) {
			String url = removeTrailingPunctuation(matcher.group());

			URI uri;
			try {
				uri = new URI(url);
			} catch (URISyntaxException e) {
				continue;
			}

			String host = uri.getHost();
			if (host == null) {
				continue;
			}

			host = host.toLowerCase(Locale.ROOT);

			int penalty;
			String reason;

			if (isBrandImpersonation(host)) {
				penalty = BRAND_IMPERSONATION_PENALTY;
				reason = String.format(BRAND_REASON_FORMAT, host);

			} else if (IPV4_PATTERN.matcher(host).matches()) {
				penalty = IP_ADDRESS_PENALTY;
				reason = String.format(IP_REASON_FORMAT, host);

			} else if (isUrlShortener(host)) {
				penalty = SHORTENED_URL_PENALTY;
				reason = String.format(SHORTENER_REASON_FORMAT, host);

			} else if (HTTP_SCHEME.equalsIgnoreCase(uri.getScheme())) {
				penalty = HTTP_PENALTY;
				reason = String.format(HTTP_REASON_FORMAT, host);

			} else {
				penalty = NO_PENALTY;
				reason = String.format(
						NO_STRUCTURAL_RISK_REASON_FORMAT, host);
			}

			if (penalty > highestPenalty) {
				highestPenalty = penalty;
				highestRiskIndex = reasons.size();
			}

			reasons.add(reason);
		}

		// Report all detected links, but apply only the highest risk penalty.
		for (int i = 0; i < reasons.size(); i++) {
			int penalty = i == highestRiskIndex
					? highestPenalty : NO_PENALTY;

			result.addPenalty(penalty, reasons.get(i));
		}

		return result;
	}

	/**
	 * Checks whether a hostname contains a trusted brand domain
	 * but does not actually belong to that domain.
	 *
	 * @param host The hostname extracted from the URL.
	 * @return True if the hostname has a suspicious brand structure.
	 */
	private boolean isBrandImpersonation(String host) {
		for (String brand : BRAND_DOMAINS) {
			if (host.equals(brand) || host.endsWith("." + brand)) {
				continue;
			}

			if (host.startsWith(brand + ".") ||
					host.contains("." + brand + ".")) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Checks whether a hostname belongs to a known URL shortening service.
	 *
	 * @param host The hostname extracted from the URL.
	 * @return True if the hostname belongs to a URL shortener.
	 */
	private boolean isUrlShortener(String host) {
		for (String shortener : URL_SHORTENERS) {
			if (host.equals(shortener) ||
					host.endsWith("." + shortener)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Removes punctuation that commonly appears directly after a URL in text.
	 *
	 * @param url The URL extracted from the email.
	 * @return The URL without trailing punctuation.
	 */
	private String removeTrailingPunctuation(String url) {
		while (!url.isEmpty() &&
				TRAILING_PUNCTUATION.indexOf(url.charAt(url.length() - 1)) >= 0) {
			url = url.substring(0, url.length() - 1);
		}

		return url;
	}
}
