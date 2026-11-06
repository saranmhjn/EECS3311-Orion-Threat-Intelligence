package ca.yorku.eecs3311.orion.llm;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;

/**
 * Constructs formatted and constrained prompts for the Large Language Model.
 * Ensures AI outputs are strictly formatted and grounded in retrieved context.
 */
public class PromptBuilder {

    /**
     * Required default constructor.
     */
    /*@ ensures true; @*/
    public PromptBuilder() {}

    /**
     * Builds a prompt for general threat landscape querying.
     * 
     * @param query The user's natural language question.
     * @param context The conversational or retrieved database context.
     * @return A formatted prompt string.
     */
    /*@
      @ requires query != null && context != null;
      @ ensures \result != null && \result.length() > 0;
      @*/
    public String buildQueryPrompt(String query, String context) {
        return "Context History:\n" + context + 
               "\n\nUser Query: " + query + 
               "\n\nAnalyze the threat landscape based on the above.";
    }

    /**
     * Builds a prompt to evaluate the triage priority of a specific vulnerability.
     */
    /*@
      @ requires advisory != null;
      @ ensures \result != null && \result.length() > 0;
      @*/
    public String buildTriagePrompt(ThreatAdvisory advisory) {
        return "Evaluate priority score for CVE: " + advisory.getId() + 
               "\nBased on vulnerability description: " + advisory.getDescription();
    }
    
    /**
     * Builds a prompt to generate a defensive mitigation playbook.
     */
    /*@
      @ requires advisory != null && env != null;
      @ ensures \result != null && \result.length() > 0;
      @*/
    public String buildMitigationPrompt(ThreatAdvisory advisory, String env) {
        return "Create step-by-step mitigation plan for " + advisory.getId() + 
               " given enterprise infrastructure: " + env;
    }
    /**
     * Builds a prompt for automated threat bulletin summarization.
     * Maps to Feature F02.
     * 
     * @param advisory The threat advisory to summarize.
     * @return A constrained prompt string.
     */
    /*@ 
      @ requires advisory != null;
      @ ensures \result != null && \result.length() > 0;
      @*/
    public String buildSummaryPrompt(ThreatAdvisory advisory) {
        return "Analyze the following technical vulnerability advisory and provide a concise " +
               "executive summary detailing the attack vector, affected systems, and operational severity:\n\n" +
               "CVE ID: " + advisory.getId() + "\n" +
               "Title: " + advisory.getTitle() + "\n" +
               "Base Severity: " + advisory.getSeverity() + "\n" +
               "Description: " + advisory.getDescription();
    }
    /**
     * Builds a prompt for dynamic vulnerability triage and priority scoring.
     * Maps to Feature F09.
     * 
     * @param advisory The threat advisory to evaluate.
     * @param techStack The enterprise infrastructure profile (e.g., "Windows Server, AWS Cloud").
     * @return A constrained prompt string.
     */
    /*@ 
      @ requires advisory != null && techStack != null;
      @ ensures \result != null && \result.length() > 0;
      @*/
    public String buildAdvancedTriagePrompt(ThreatAdvisory advisory, String techStack) {
        return "Perform a dynamic vulnerability triage and assign a customized priority score " +
               "(CRITICAL, HIGH, MEDIUM, LOW) based on the following advisory and target infrastructure:\n\n" +
               "CVE ID: " + advisory.getId() + "\n" +
               "Base Severity: " + advisory.getSeverity() + "\n" +
               "Description: " + advisory.getDescription() + "\n\n" +
               "Target Enterprise Tech Stack: " + techStack + "\n" +
               "Provide the calibrated priority score and a brief tactical justification.";
    }
}