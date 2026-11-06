package ca.yorku.eecs3311.orion.llm;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import ca.yorku.eecs3311.orion.tool.LogParserTool;
import ca.yorku.eecs3311.orion.tool.ToolManager;

import java.util.Map;

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
}