package ca.yorku.eecs3311.orion.controller;

import ca.yorku.eecs3311.orion.api.AdvisoryParser;
import ca.yorku.eecs3311.orion.api.AdvisoryParserFactory;
import ca.yorku.eecs3311.orion.api.NvdApiClient;
import ca.yorku.eecs3311.orion.command.CommandManager;
import ca.yorku.eecs3311.orion.command.SecurityCommand;
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
    private AgentFacade agentFacade;
    
    // Added the command execution manager
    private CommandManager commandManager;

    /*@ public invariant advisoryRepo != null; @*/
    /*@ public invariant apiClient != null; @*/
    /*@ public invariant parserFactory != null; @*/
    /*@ public invariant agentFacade != null; @*/
    /*@ public invariant commandManager != null; @*/

    /*@ 
      @ requires dbManager != null;
      @*/
    public AgentController(DatabaseManager dbManager) {
        this.advisoryRepo = new AdvisoryRepository(dbManager.getConnection());
        this.apiClient = new NvdApiClient();
        this.parserFactory = new AdvisoryParserFactory();
        this.agentFacade = new AgentFacade(new GeminiLLMClient());
        
        // Initialize the command manager to track defensive actions
        this.commandManager = new CommandManager();
    }

    /*@ requires source != null && source.length() > 0; @*/
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

    /*@
      @ requires query != null && query.length() > 0;
      @ ensures \result != null;
      @*/
    public String handleNaturalQuery(String query) {
        return agentFacade.processGoal(query);
    }
    
    /**
     * Executes an AI-generated security mitigation.
     * Maps to Feature F05 and SD-03.
     */
    /*@ requires cmd != null; @*/
    public boolean executeCommand(SecurityCommand cmd) {
        return commandManager.invoke(cmd);
    }
    
    /**
     * Rolls back the last executed security mitigation.
     */
    public boolean undoLastCommand() {
        return commandManager.undoLast();
    }
}