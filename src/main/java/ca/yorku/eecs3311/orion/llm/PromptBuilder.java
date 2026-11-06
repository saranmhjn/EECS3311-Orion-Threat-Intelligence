package ca.yorku.eecs3311.orion.llm;

import java.util.List;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;

/**
 * Constructs highly constrained, bulletproof prompts for the Orion AI.
 * Enforces strict structural formatting and bans tables and paragraphs.
 */
public class PromptBuilder {

    public PromptBuilder() {}

    public String buildQueryPrompt(String query, String context) {
        return "You are Orion, a Cyber Threat Intelligence Assistant.\n" +
               "Current Query: " + query + "\n" +
               "Context: " + context + "\n\n" +
               "CRITICAL RULES:\n" +
               "1. Start with the header: ### General Inquiry\n" +
               "2. Answer in 2-3 direct, short bullet points.\n" +
               "3. NO markdown tables. NO long paragraphs. NO conversational filler.";
    }

    public String buildSummaryPrompt(ThreatAdvisory advisory) {
        return "Summarize CVE: " + advisory.getId() + " - " + advisory.getTitle() + "\n" +
               "Description: " + advisory.getDescription() + "\n\n" +
               "CRITICAL RULES:\n" +
               "1. Start with the header: ### Executive Summary for " + advisory.getId() + "\n" +
               "2. NO markdown tables. NO long paragraphs.\n" +
               "3. Use exactly this structure with single-sentence bullet points:\n\n" +
               "**Attack Vector**\n- [Point]\n\n" +
               "**Operational Impact**\n- [Point]\n\n" +
               "**Affected Systems**\n- [Point]";
    }

    public String buildMitigationPrompt(ThreatAdvisory advisory, String environment) {
        return "Generate a Mitigation Playbook for " + advisory.getId() + " in: " + environment + ".\n" +
               "Description: " + advisory.getDescription() + "\n\n" +
               "CRITICAL RULES:\n" +
               "1. Start with the header: ### Mitigation Playbook for " + advisory.getId() + "\n" +
               "2. NO markdown tables. NO paragraphs.\n" +
               "3. Use exactly this structure with precise, single-sentence bullet points:\n\n" +
               "**Patching Strategy**\n- [Point]\n\n" +
               "**Temporary Workarounds**\n- [Point]\n\n" +
               "**Threat Hunting / Monitoring**\n- [Point]";
    }

    public String buildAdvancedTriagePrompt(ThreatAdvisory advisory, String techStack) {
        return "Calibrate priority for CVE: " + advisory.getId() + " against stack: " + techStack + ".\n" +
               "Severity: " + advisory.getSeverity() + " | Description: " + advisory.getDescription() + "\n\n" +
               "CRITICAL RULES:\n" +
               "1. Start with the header: ### Dynamic Triage for " + advisory.getId() + "\n" +
               "2. NO markdown tables. NO paragraphs.\n" +
               "3. Use exactly this structure with single-sentence bullet points:\n\n" +
               "**Tactical Priority**\n- [Score: CRITICAL/HIGH/MEDIUM/LOW]\n\n" +
               "**Applicability**\n- [Point]\n\n" +
               "**SLA Recommendation**\n- [Point]";
    }

    public String buildGapAnalysisPrompt(ThreatAdvisory advisory, List<String> controls) {
        return "Security Control Gap Analysis for " + advisory.getId() + " against controls: " + String.join(", ", controls) + ".\n" +
               "Advisory: " + advisory.getDescription() + "\n\n" +
               "CRITICAL RULES:\n" +
               "1. Start with the header: ### Gap Analysis for " + advisory.getId() + "\n" +
               "2. Absolutely NO markdown tables (do not use '|'). NO long paragraphs.\n" +
               "3. Use exactly this structure with short, punchy bullet points:\n\n" +
               "**Active Coverage**\n- [Point]\n\n" +
               "**Blind Spots**\n- [Point]\n\n" +
               "**Remediation Gaps**\n- [Point]\n\n" +
               "**Immediate Recommendation**\n- [Point]";
    }

    public String buildTriagePrompt(ThreatAdvisory advisory) {
        return "Priority triage evaluation for CVE ID: " + advisory.getId() + ".\n" +
               "Payload: " + advisory.getDescription() + "\n\n" +
               "Start with header: ### Triage Evaluation for " + advisory.getId() + "\n" +
               "Provide 3 short bullet points. NO tables.";
    }
}