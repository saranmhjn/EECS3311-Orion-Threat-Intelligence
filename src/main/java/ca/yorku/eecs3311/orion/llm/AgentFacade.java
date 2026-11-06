package ca.yorku.eecs3311.orion.llm;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import ca.yorku.eecs3311.orion.tool.LogParserTool;
import ca.yorku.eecs3311.orion.tool.ToolManager;

import java.util.List;

/**
 * The Facade pattern entry point for all non-deterministic AI capabilities.
 */
public class AgentFacade {

    private LLMClient llmClient;
    private AgentMemoryManager memory;
    private PromptBuilder promptBuilder;
    private ToolManager toolManager;

    /*@ public invariant llmClient != null; @*/
    /*@ public invariant memory != null; @*/
    /*@ public invariant promptBuilder != null; @*/
    /*@ public invariant toolManager != null; @*/

    /*@
      @ requires llmClient != null;
      @*/
    public AgentFacade(LLMClient llmClient) {
        this.llmClient = llmClient;
        this.memory = new AgentMemoryManager();
        this.promptBuilder = new PromptBuilder();
        
        // Initialize the ToolManager and register the agent's deterministic tools
        this.toolManager = new ToolManager();
        this.toolManager.registerTool(new LogParserTool());
    }

    /*@ requires goal != null && goal.length() > 0; @*/
    public String processGoal(String goal) {
        try {
            memory.appendContext("User Query: " + goal);
            String context = memory.retrieveContext();
            String prompt = promptBuilder.buildQueryPrompt(goal, context);
            String response = llmClient.generate(prompt);
            memory.appendContext("Agent Response: " + response);
            return response;
        } catch (Exception e) {
            return "AI Processing Error: " + e.getMessage();
        }
    }

    /*@ requires advisory != null; @*/
    public String evaluateTriage(ThreatAdvisory advisory) {
        try {
            String prompt = promptBuilder.buildTriagePrompt(advisory);
            return llmClient.generate(prompt);
        } catch (Exception e) {
            return "Triage Error: " + e.getMessage();
        }
    }

    /**
     * Exposes the ToolManager so the AgentController can trigger deterministic tools 
     * prior to passing data to the LLM.
     */
    /*@ ensures \result != null; @*/
    public ToolManager getToolManager() {
        return this.toolManager;
    }

    /**
     * Generates an executive summary for a threat advisory.
     * Maps to Feature F02 and Use Case UC-02.
     * 
     * @param advisory The ThreatAdvisory to summarize.
     * @return The AI-generated executive summary.
     */
    /*@ 
      @ requires advisory != null;
      @ ensures \result != null;
      @*/
    public String summarizeAdvisory(ThreatAdvisory advisory) {
        try {
            String prompt = promptBuilder.buildSummaryPrompt(advisory);
            return llmClient.generate(prompt);
        } catch (Exception e) {
            return "Summarization Error: " + e.getMessage();
        }
    }

    /**
     * Evaluates a threat advisory against organizational infrastructure for dynamic triage.
     * Maps to Feature F09 and Use Case UC-04[cite: 10, 20].
     * 
     * @param advisory The ThreatAdvisory to evaluate.
     * @param techStack The enterprise infrastructure profile.
     * @return The AI-generated triage assessment and score.
     */
    /*@ 
      @ requires advisory != null && techStack != null;
      @ ensures \result != null;
      @*/
    public String evaluateDynamicTriage(ThreatAdvisory advisory, String techStack) {
        try {
            String prompt = promptBuilder.buildAdvancedTriagePrompt(advisory, techStack);
            return llmClient.generate(prompt);
        } catch (Exception e) {
            return "Triage Evaluation Error: " + e.getMessage();
        }
    }

    /**
     * Generates an automated mitigation playbook for a specific threat advisory.
     * Maps to Feature F05 and Use Case UC-04[cite: 8, 20].
     * 
     * @param advisory The target ThreatAdvisory.
     * @param env The target environment configuration.
     * @return The AI-generated mitigation playbook.
     */
    /*@ 
      @ requires advisory != null && env != null;
      @ ensures \result != null;
      @*/
    public String planMitigation(ThreatAdvisory advisory, String env) {
        try {
            String prompt = promptBuilder.buildMitigationPrompt(advisory, env);
            return llmClient.generate(prompt);
        } catch (Exception e) {
            return "Mitigation Planning Error: " + e.getMessage();
        }
    }

    /**
     * Evaluates active enterprise security controls against a threat profile.
     * Maps to Feature F10 and Use Case UC-08[cite: 9, 21, 36].
     * 
     * @param advisory The ThreatAdvisory to evaluate.
     * @param controls List of active security controls.
     * @return The AI-generated gap analysis matrix.
     */
    /*@ 
      @ requires advisory != null && controls != null;
      @ ensures \result != null;
      @*/
    public String evaluateGaps(ThreatAdvisory advisory, List<String> controls) {
        try {
            String prompt = promptBuilder.buildGapAnalysisPrompt(advisory, controls);
            return llmClient.generate(prompt);
        } catch (Exception e) {
            return "Gap Analysis Error: " + e.getMessage();
        }
    }
}