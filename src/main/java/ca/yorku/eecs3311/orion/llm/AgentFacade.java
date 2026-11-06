package ca.yorku.eecs3311.orion.llm;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;

/**
 * The Facade pattern entry point for all non-deterministic AI capabilities.
 */
public class AgentFacade {

    private LLMClient llmClient;
    private AgentMemoryManager memory;
    private PromptBuilder promptBuilder;

    /*@ public invariant llmClient != null; @*/
    /*@ public invariant memory != null; @*/
    /*@ public invariant promptBuilder != null; @*/

    /*@
      @ requires llmClient != null;
      @ ensures this.llmClient == llmClient;
      @ ensures this.memory != null;
      @ ensures this.promptBuilder != null;
      @*/
    public AgentFacade(LLMClient llmClient) {
        this.llmClient = llmClient;
        this.memory = new AgentMemoryManager();
        this.promptBuilder = new PromptBuilder();
    }

    /*@
      @ requires goal != null && goal.length() > 0;
      @ ensures \result != null;
      @*/
    public String processGoal(String goal) {
        try {
            memory.appendContext("User Query: " + goal);
            String context = memory.retrieveContext();
            
            // Use PromptBuilder to format the payload
            String prompt = promptBuilder.buildQueryPrompt(goal, context);
            
            String response = llmClient.generate(prompt);
            memory.appendContext("Agent Response: " + response);
            return response;
            
        } catch (Exception e) {
            return "AI Processing Error: " + e.getMessage();
        }
    }

    /*@
      @ requires advisory != null;
      @ ensures \result != null;
      @*/
    public String evaluateTriage(ThreatAdvisory advisory) {
        try {
            // Use PromptBuilder to format the payload
            String prompt = promptBuilder.buildTriagePrompt(advisory);
            return llmClient.generate(prompt);
        } catch (Exception e) {
            return "Triage Error: " + e.getMessage();
        }
    }
}