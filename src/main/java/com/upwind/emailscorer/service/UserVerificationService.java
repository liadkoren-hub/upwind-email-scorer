
package com.upwind.emailscorer.service;

import com.upwind.emailscorer.dto.VerifyRequest;
import com.upwind.emailscorer.dto.VerifyResponse;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service responsible for managing and validating user verification status.
 * Implements a "Proof of Inbox History" mechanism to prevent Sybil attacks and bots.
 * Users must prove ownership of an active inbox by submitting a required number
 * of historical emails that meet specific age, interval, and unique sender criteria.
 *
 * @author Liad Koren
 */
@Service
public class UserVerificationService {

	private static final int REQUIRED_EMAILS = 2;

	private static final long HOURS_IN_DAY = 24L;
	private static final long MINUTES_IN_HOUR = 60L;
	private static final long SECONDS_IN_MINUTE = 60L;
	private static final long MS_IN_SECOND = 1000L;
	private static final long MS_PER_DAY = HOURS_IN_DAY * MINUTES_IN_HOUR * SECONDS_IN_MINUTE * MS_IN_SECOND;

	private static final long MIN_AGE_DAYS = 90L;
	private static final long MIN_INTERVAL_DAYS = 3L;

	private static final long MIN_AGE_MS = MIN_AGE_DAYS * MS_PER_DAY;
	private static final long MIN_INTERVAL_MS = MIN_INTERVAL_DAYS * MS_PER_DAY;

	private static final int ZERO_PROGRESS = 0;

	private static final String ERROR_MISSING_USER =
			"שגיאה: חסר זיהוי משתמש.";
	private static final String SUCCESS_ALREADY_VERIFIED =
			"החשבון שלך כבר מאומת!";
	private static final String ERROR_EMAIL_NOT_OLD_ENOUGH_FORMAT =
			"האימייל אינו ישן מספיק. נדרש אימייל בן %d יום לפחות.";
	private static final String ERROR_DUPLICATE_SENDER =
			"כבר אימתת בעבר אימייל מהשולח הזה. בחר שולח אחר.";
	private static final String ERROR_DATE_TOO_CLOSE_FORMAT =
			"תאריך האימייל קרוב מדי לאימייל אחר שאימתת. נדרש הפרש של %d ימים.";
	private static final String SUCCESS_FULLY_VERIFIED =
			"כל הכבוד! החשבון אומת בהצלחה והתוסף פתוח לשימוש.";
	private static final String SUCCESS_PROGRESS_FORMAT =
			"מעולה! אימייל נוסף אושר. נותרו עוד %d.";

	private final ConcurrentHashMap<String, UserVerificationState> userStates;

	/**
	 * Constructs the UserVerificationService and initializes the state map.
	 */
	public UserVerificationService() {
		this.userStates = new ConcurrentHashMap<>();
	}

	/**
	 * Processes a verification request from a user, validating the submitted email's
	 * age, sender uniqueness, and time interval relative to previously verified emails.
	 * Synchronizes validation and state updates to prevent concurrent verification conflicts.
	 *
	 * @param request The verification request containing user and email details.
	 * @return A VerifyResponse indicating success, failure, and current progress.
	 */
	public VerifyResponse processVerification(VerifyRequest request) {
		String userEmail = request.getUserEmail();
		if (userEmail == null || userEmail.isEmpty()) {
			return createVerifyResponse(false, ZERO_PROGRESS, ERROR_MISSING_USER);
		}

		String normalizedUserEmail = userEmail.toLowerCase().trim();
		long currentTime = System.currentTimeMillis();

		UserVerificationState state = userStates.get(normalizedUserEmail);
		if (state == null) {
			UserVerificationState newState = new UserVerificationState();
			UserVerificationState existingState = userStates.putIfAbsent(normalizedUserEmail, newState);

			if (existingState != null) {
				state = existingState;
			} else {
				state = newState;
			}
		}

		// Ensure that validation and state updates are atomic for each user.
		synchronized (state) {

			if (state.isFullyVerified()) {
				return createVerifyResponse(true, REQUIRED_EMAILS, SUCCESS_ALREADY_VERIFIED);
			}

			long ageOfEmailMs = currentTime - request.getEmailDateMs();
			if (ageOfEmailMs < MIN_AGE_MS) {
				String errorMessage = String.format(ERROR_EMAIL_NOT_OLD_ENOUGH_FORMAT, MIN_AGE_DAYS);
				return createVerifyResponse(false, state.getProgress(), errorMessage);
			}

			String normalizedSender = request.getEmailSender().toLowerCase().trim();

			for (VerifiedEmail existing : state.getVerifiedEmails()) {
				if (existing.getSender().equals(normalizedSender)) {
					return createVerifyResponse(false, state.getProgress(), ERROR_DUPLICATE_SENDER);
				}

				long timeDifference = Math.abs(existing.getDateMs() - request.getEmailDateMs());
				if (timeDifference < MIN_INTERVAL_MS) {
					String errorMessage = String.format(ERROR_DATE_TOO_CLOSE_FORMAT, MIN_INTERVAL_DAYS);
					return createVerifyResponse(false, state.getProgress(), errorMessage);
				}
			}

			state.addEmail(new VerifiedEmail(normalizedSender, request.getEmailDateMs()));

			if (state.isFullyVerified()) {
				return createVerifyResponse(true, REQUIRED_EMAILS, SUCCESS_FULLY_VERIFIED);
			} else {
				int remainingEmails = REQUIRED_EMAILS - state.getProgress();
				String progressMessage = String.format(SUCCESS_PROGRESS_FORMAT, remainingEmails);
				return createVerifyResponse(false, state.getProgress(), progressMessage);
			}
		}
	}

	/**
	 * Creates a verification response using the current verification requirements.
	 *
	 * @param fullyVerified True if the user has completed verification.
	 * @param progress      The user's current verification progress.
	 * @param message       A message describing the verification result.
	 * @return A VerifyResponse containing the result and verification requirements.
	 */
	private VerifyResponse createVerifyResponse(boolean fullyVerified,
												int progress,
												String message) {
		return new VerifyResponse(
				fullyVerified,
				progress,
				message,
				REQUIRED_EMAILS,
				MIN_AGE_DAYS,
				MIN_INTERVAL_DAYS
		);
	}

	/**
	 * Retrieves the current verification status and requirements of a user.
	 * Returns the stored progress without modifying the user's verification state.
	 *
	 * @param userEmail The authenticated user's email address.
	 * @return A VerifyResponse containing the current verification status and requirements.
	 */
	public VerifyResponse getVerificationStatus(String userEmail) {
		String normalizedUserEmail = userEmail.toLowerCase().trim();

		UserVerificationState state = userStates.get(normalizedUserEmail);

		int progress = state == null ? ZERO_PROGRESS : state.getProgress();
		boolean fullyVerified = progress >= REQUIRED_EMAILS;

		return createVerifyResponse(fullyVerified, progress, "");
	}

	/**
	 * Checks whether a specific user has completed the entire verification process.
	 *
	 * @param userEmail The email address of the user to check.
	 * @return True if the user is fully verified, false otherwise.
	 */
	public boolean isUserVerified(String userEmail) {
		if (userEmail == null) {
			return false;
		}

		UserVerificationState state = userStates.get(userEmail.toLowerCase().trim());
		return state != null && state.isFullyVerified();
	}

	/**
	 * Internal class representing the verification state of a single user.
	 * Maintains a list of emails that have been successfully verified.
	 */
	private static class UserVerificationState {
		private final List<VerifiedEmail> verifiedEmails = new ArrayList<>();

		/**
		 * Adds a newly verified email to the user's state.
		 * Synchronized to ensure thread-safety during concurrent updates.
		 *
		 * @param email The verified email object.
		 */
		public synchronized void addEmail(VerifiedEmail email) {
			verifiedEmails.add(email);
		}

		/**
		 * Retrieves the list of currently verified emails.
		 *
		 * @return A list of VerifiedEmail objects.
		 */
		public synchronized List<VerifiedEmail> getVerifiedEmails() {
			return verifiedEmails;
		}

		/**
		 * Gets the current number of successfully verified emails.
		 *
		 * @return The verification progress count.
		 */
		public synchronized int getProgress() {
			return verifiedEmails.size();
		}

		/**
		 * Checks if the user has reached the required number of verified emails.
		 *
		 * @return True if fully verified, false otherwise.
		 */
		public synchronized boolean isFullyVerified() {
			return verifiedEmails.size() >= REQUIRED_EMAILS;
		}
	}

	/**
	 * Internal class representing a single verified email.
	 * Stores the sender and the date the email was received.
	 */
	private static class VerifiedEmail {
		private final String sender;
		private final long dateMs;

		/**
		 * Constructs a VerifiedEmail object.
		 *
		 * @param sender The sender's email address.
		 * @param dateMs The timestamp of the email in milliseconds since epoch.
		 */
		public VerifiedEmail(String sender, long dateMs) {
			this.sender = sender;
			this.dateMs = dateMs;
		}

		/**
		 * Gets the sender's email address.
		 *
		 * @return The sender's email address.
		 */
		public String getSender() {
			return sender;
		}

		/**
		 * Gets the email's timestamp.
		 *
		 * @return The timestamp in milliseconds.
		 */
		public long getDateMs() {
			return dateMs;
		}
	}
}
