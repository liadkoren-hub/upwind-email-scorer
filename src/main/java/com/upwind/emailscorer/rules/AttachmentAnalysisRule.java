
package com.upwind.emailscorer.rules;

import com.upwind.emailscorer.dto.EmailRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * This class implements the attachment analysis rule.
 * It analyzes attachment filename extensions to identify potentially
 * dangerous executable files, scripts, macro-enabled documents,
 * and common document types.
 * Reports all recognized attachments while applying a penalty
 * based on the highest detected risk level.
 * Does not inspect the actual contents of the attachments.
 *
 * @author Liad Koren
 */
public class AttachmentAnalysisRule implements EmailScannerRule {

	private static final Set<String> DANGEROUS_EXTENSIONS = Set.of(
			"exe", "bat", "cmd", "scr", "vbs", "js", "wsf", "ps1",
			"com", "msi", "hta"
	);

	private static final Set<String> MACRO_EXTENSIONS = Set.of(
			"docm", "xlsm", "pptm", "xlsb"
	);

	private static final Set<String> COMMON_DOCUMENT_EXTENSIONS = Set.of(
			"pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt"
	);

	private static final int DANGEROUS_EXTENSION_PENALTY = 70;
	private static final int MACRO_EXTENSION_PENALTY = 35;
	private static final int COMMON_DOCUMENT_PENALTY = 5;
	private static final int NO_PENALTY = 0;

	private static final String DANGEROUS_EXTENSION_REASON_FORMAT =
			"זוהתה סיומת של קובץ הרצה או סקריפט שעלול להיות מסוכן (%s)";

	private static final String MACRO_EXTENSION_REASON_FORMAT =
			"זוהה מסמך שתומך במאקרו ועלול להכיל קוד זדוני (%s)";

	private static final String COMMON_DOCUMENT_REASON_FORMAT =
			"זוהה קובץ מסמך נפוץ שמצריך בדיקה בסיסית (%s)";

	private static final char EXTENSION_SEPARATOR = '.';
	private static final int NOT_FOUND = -1;
	private static final int EXTENSION_OFFSET = 1;

	/**
	 * Analyzes all email attachments based on their filename extensions.
	 * Reports each recognized attachment, but applies only the highest
	 * risk penalty to avoid accumulating points for multiple files.
	 *
	 * @param request The incoming email request containing the attachment names.
	 * @return A RuleResult object containing penalty points and reasons.
	 */
	@Override
	public RuleResult analyze(EmailRequest request) {
		RuleResult result = new RuleResult();
		List<String> attachments = request.getAttachmentNames();

		if (attachments == null || attachments.isEmpty()) {
			return result;
		}

		List<String> reasons = new ArrayList<>();
		int highestPenalty = NO_PENALTY;
		int highestRiskIndex = NOT_FOUND;

		for (String filename : attachments) {
			if (filename == null || filename.isBlank()) {
				continue;
			}

			String extension = getFileExtension(filename)
					.toLowerCase(Locale.ROOT);

			int penalty;
			String reason;

			if (DANGEROUS_EXTENSIONS.contains(extension)) {
				penalty = DANGEROUS_EXTENSION_PENALTY;
				reason = String.format(DANGEROUS_EXTENSION_REASON_FORMAT, filename);

			} else if (MACRO_EXTENSIONS.contains(extension)) {
				penalty = MACRO_EXTENSION_PENALTY;
				reason = String.format(MACRO_EXTENSION_REASON_FORMAT, filename);

			} else if (COMMON_DOCUMENT_EXTENSIONS.contains(extension)) {
				penalty = COMMON_DOCUMENT_PENALTY;
				reason = String.format(COMMON_DOCUMENT_REASON_FORMAT, filename);

			} else {
				continue;
			}

			if (penalty > highestPenalty) {
				highestPenalty = penalty;
				highestRiskIndex = reasons.size();
			}

			reasons.add(reason);
		}

		// Report every recognized attachment, but add the risk penalty only once.
		for (int i = 0; i < reasons.size(); i++) {
			int penalty = (i == highestRiskIndex)
					? highestPenalty : NO_PENALTY;

			result.addPenalty(penalty, reasons.get(i));
		}

		return result;
	}

	/**
	 * Extracts the file extension from a given filename.
	 *
	 * @param filename The full name of the file.
	 * @return The extension without the dot, or an empty string if none is found.
	 */
	private String getFileExtension(String filename) {
		String normalizedFilename = filename.trim();
		int dotIndex = normalizedFilename.lastIndexOf(EXTENSION_SEPARATOR);

		if (dotIndex == NOT_FOUND || dotIndex == normalizedFilename.length() - 1) {
			return "";
		}

		return normalizedFilename.substring(dotIndex + EXTENSION_OFFSET);
	}
}
