package com.upwind.emailscorer.dto;

import java.util.List;

/**
 * A Data Transfer Object (DTO) representing the final result of an email scan.
 * Contains the aggregated score, the definitive verdict, and a list of reasons.
 *
 * @author Liad Koren
 */
public class ScanResponse {

	private int score;
	private String verdict;
	private List<String> reasons;

	/**
	 * Constructs a ScanResponse with the given evaluation results.
	 *
	 * @param score   The total penalty score calculated for the email.
	 * @param verdict The final classification (e.g., Safe, Suspicious, Malicious).
	 * @param reasons A list of descriptive reasons for the applied penalties.
	 */
	public ScanResponse(int score, String verdict, List<String> reasons) {
		this.score = score;
		this.verdict = verdict;
		this.reasons = reasons;
	}

	/**
	 * Gets the total calculated penalty score.
	 *
	 * @return The penalty score.
	 */
	public int getScore() {
		return score;
	}

	/**
	 * Sets the total calculated penalty score.
	 *
	 * @param score The penalty score.
	 */
	public void setScore(int score) {
		this.score = score;
	}

	/**
	 * Gets the final verdict of the scan.
	 *
	 * @return The verdict string.
	 */
	public String getVerdict() {
		return verdict;
	}

	/**
	 * Sets the final verdict of the scan.
	 *
	 * @param verdict The verdict string.
	 */
	public void setVerdict(String verdict) {
		this.verdict = verdict;
	}

	/**
	 * Gets the list of reasons explaining the verdict.
	 *
	 * @return A list of descriptive reasons.
	 */
	public List<String> getReasons() {
		return reasons;
	}

	/**
	 * Sets the list of reasons explaining the verdict.
	 *
	 * @param reasons A list of descriptive reasons.
	 */
	public void setReasons(List<String> reasons) {
		this.reasons = reasons;
	}
}