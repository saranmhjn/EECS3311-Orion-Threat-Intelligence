package ca.yorku.eecs3311.orion.llm;

import java.util.List;

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
        return "You are Orion, an autonomous Cyber Threat Intelligence AI assistant. " +
               "Respond conversationally, accurately, and concisely.\n\n" +
               "Context History:\n" + context + 
               "\n\nUser Query: " + query + 
               "\n\nIf the user is greeting you or asking about your capabilities, answer naturally. " +
               "If the user is asking a cybersecurity question (like 'what is a zero-day'), explain it clearly without over-analyzing the user's intent.";
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
     * Maps to Feature F05[cite: 8, 34].
     * 
     * @param advisory The threat advisory requiring mitigation.
     * @param env The enterprise infrastructure profile.
     * @return A constrained prompt string.
     */
    /*@ 
      @ requires advisory != null && env != null;
      @ ensures \result != null && \result.length() > 0;
      @*/
    public String buildMitigationPrompt(ThreatAdvisory advisory, String env) {
        return "Create a step-by-step technical mitigation playbook for vulnerability " + advisory.getId() + 
               " (" + advisory.getTitle() + ")\n" +
               "Vulnerability Description: " + advisory.getDescription() + "\n\n" +
               "Target Enterprise Environment: " + env + "\n" +
               "Provide clear remediation steps, including specific configuration changes or firewall rules.";
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

    /**
     * Builds a prompt for evaluating enterprise security control gaps against a threat.
     * Maps to Feature F10[cite: 9, 10].
     * 
     * @param advisory The target threat advisory.
     * @param controls List of active enterprise security controls.
     * @return A constrained prompt string.
     */
    /*@ 
      @ requires advisory != null && controls != null;
      @ ensures \result != null && \result.length() > 0;
      @*/
    public String buildGapAnalysisPrompt(ThreatAdvisory advisory, List<String> controls) {
        return "Perform a Security Control Gap Analysis for vulnerability " + advisory.getId() + 
               " (" + advisory.getTitle() + ")\n" +
               "Description: " + advisory.getDescription() + "\n\n" +
               "Active Enterprise Security Controls: " + String.join(", ", controls) + "\n\n" +
               "Identify unmitigated attack vectors and provide a structured gap matrix with recommendations.";
    }
}