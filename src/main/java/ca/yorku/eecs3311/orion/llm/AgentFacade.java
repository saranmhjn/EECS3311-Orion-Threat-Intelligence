package ca.yorku.eecs3311.orion.llm;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;

/**
 * The Facade pattern entry point for all non-deterministic AI capabilities.
 * Orchestrates memory, planning, and external LLM communication, 
 * shielding the boundary layer from AI subsystem complexities.
 */
public class AgentFacade {

    private LLMClient llmClient;
    private AgentMemoryManager memory;

    /*@ public invariant llmClient != null; @*/
    /*@ public invariant memory != null; @*/

    /**
     * Initializes the Facade and its encapsulated subsystems.
     */
    /*@
      @ requires llmClient != null;
      @ ensures this.llmClient == llmClient;
      @ ensures this.memory != null;
      @*/
    public AgentFacade(LLMClient llmClient) {
        this.llmClient = llmClient;
        this.memory = new AgentMemoryManager();
    }

    /**
     * Processes a high-level natural language goal from the user.
     * Maps to Feature F03 (Natural Language Threat Landscape Querying).
     * 
     * @param goal The natural language query or task.
     * @return The synthesized response from the AI.
     */
    /*@
      @ requires goal != null && goal.length() > 0;
      @ ensures \result != null;
      @*/
    public String processGoal(String goal) {
        try {
            // 1. Log the user's query into memory
            memory.appendContext("User Query: " + goal);
            
            // 2. Retrieve the full conversation context
            String context = memory.retrieveContext();
            
            // 3. Formulate the prompt combining memory and the new goal
            String prompt = "Context History:\n" + context + "\n\nAnalyze the threat landscape based on the above.";
            
            // 4. Send to the LLM and capture the response
            String response = llmClient.generate(prompt);
            
            // 5. Log the AI's response into memory to maintain future context
            memory.appendContext("Agent Response: " + response);
            
            return response;
            
        } catch (Exception e) {
            return "AI Processing Error: " + e.getMessage();
        }
    }

    /**
     * Evaluates a specific threat advisory to assign a qualitative triage score.
     * Maps to Feature F09 (Dynamic Advisory Triage).
     */
    /*@
      @ requires advisory != null;
      @ ensures \result != null;
      @*/
    public String evaluateTriage(ThreatAdvisory advisory) {
        try {
            String prompt = "Evaluate priority score for CVE: " + advisory.getId() + 
                            "\nBased on vulnerability description: " + advisory.getDescription();
            return llmClient.generate(prompt);
        } catch (Exception e) {
            return "Triage Error: " + e.getMessage();
        }
    }
}