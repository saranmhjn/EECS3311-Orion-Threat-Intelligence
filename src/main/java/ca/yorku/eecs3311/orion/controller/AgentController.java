package ca.yorku.eecs3311.orion.controller;

import ca.yorku.eecs3311.orion.api.AdvisoryParser;
import ca.yorku.eecs3311.orion.api.AdvisoryParserFactory;
import ca.yorku.eecs3311.orion.api.NvdApiClient;
import ca.yorku.eecs3311.orion.database.DatabaseManager;
import ca.yorku.eecs3311.orion.llm.AgentFacade;
import ca.yorku.eecs3311.orion.llm.GeminiLLMClient;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import ca.yorku.eecs3311.orion.repository.AdvisoryRepository;

import java.util.List;

/**
 * The central deterministic orchestrator for the Orion Threat Intelligence system.
 */
public class AgentController {

    private AdvisoryRepository advisoryRepo;
    private NvdApiClient apiClient;
    private AdvisoryParserFactory parserFactory;
    
    // Added the AI orchestration layer
    private AgentFacade agentFacade;

    /*@ public invariant advisoryRepo != null; @*/
    /*@ public invariant apiClient != null; @*/
    /*@ public invariant parserFactory != null; @*/
    /*@ public invariant agentFacade != null; @*/

    /*@ 
      @ requires dbManager != null;
      @*/
    public AgentController(DatabaseManager dbManager) {
        this.advisoryRepo = new AdvisoryRepository(dbManager.getConnection());
        this.apiClient = new NvdApiClient();
        this.parserFactory = new AdvisoryParserFactory();
        
        // Initialize the AI Facade with our specific Gemini client
        this.agentFacade = new AgentFacade(new GeminiLLMClient());
    }

    /*@
      @ requires source != null && source.length() > 0;
      @*/
    public void syncFeeds(String source) {
        try {
            String rawData = apiClient.fetchRawAdvisories();
            AdvisoryParser parser = parserFactory.createParser("JSON");
            List<ThreatAdvisory> advisories = parser.parse(rawData);
            advisoryRepo.saveAll(advisories);
            System.out.println("Successfully synchronized " + advisories.size() + " advisories from " + source);
        } catch (Exception e) {
            System.err.println("Failed to sync feeds: " + e.getMessage());
        }
    }

    /**
     * Bridges the boundary layer (GUI/CLI) to the AI reasoning engine.
     * Maps to Feature F03 and Sequence Diagram SD-01.
     * 
     * @param query The user's chat input.
     * @return The AI-generated contextual response.
     */
    /*@
      @ requires query != null && query.length() > 0;
      @ ensures \result != null;
      @*/
    public String handleNaturalQuery(String query) {
        // Delegates complex prompt building and API calls to the Facade
        return agentFacade.processGoal(query);
    }
}