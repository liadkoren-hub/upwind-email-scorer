package com.upwind.emailscorer.rules;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents the outcome of an individual email scanning rule.
 * Contains the accumulated penalty points and the specific reasons for those penalties.
 *
 * @author Liad Koren
 */
public class RuleResult {

	private static final int INITIAL_PENALTY_POINTS = 0;

	private int penaltyPoints;
	private List<String> reasons;

	/**
	 * Default constructor. Initializes the rule result with zero penalty points
	 * and an empty list of reasons.
	 */
	public RuleResult() {
		this.penaltyPoints = INITIAL_PENALTY_POINTS;
		this.reasons = new ArrayList<>();
	}

	/**
	 * Adds penalty points and an accompanying reason to this rule result.
	 * This method acts as a convenient helper for rules to accumulate penalties.
	 *
	 * @param points The number of penalty points to add.
	 * @param reason A descriptive reason for the applied penalty.
	 */
	public void addPenalty(int points, String reason) {
		this.penaltyPoints += points;
		this.reasons.add(reason);
	}

	/**
	 * Gets the total accumulated penalty points for this rule.
	 *
	 * @return The total penalty points.
	 */
	public int getPenaltyPoints() {
		return penaltyPoints;
	}

	/**
	 * Gets the list of reasons explaining the applied penalties.
	 *
	 * @return A list of descriptive reasons.
	 */
	public List<String> getReasons() {
		return reasons;
	}
}