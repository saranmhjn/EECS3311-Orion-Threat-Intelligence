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
import ca.yorku.eecs3311.orion.observer.SecurityObserver;

import java.util.ArrayList;
import java.util.List;

/**
 * The central deterministic orchestrator for the Orion Threat Intelligence system.
 * Acts as the Subject in the Observer Pattern to notify boundary layers of state changes.
 */
public class AgentController {

    private AdvisoryRepository advisoryRepo;
    private NvdApiClient apiClient;
    private AdvisoryParserFactory parserFactory;
    private AgentFacade agentFacade;
    private CommandManager commandManager;
    
    // Observer list for broadcasting asynchronous events
    private List<SecurityObserver> observers;

    /*@ public invariant advisoryRepo != null; @*/
    /*@ public invariant apiClient != null; @*/
    /*@ public invariant parserFactory != null; @*/
    /*@ public invariant agentFacade != null; @*/
    /*@ public invariant commandManager != null; @*/
    /*@ public invariant observers != null; @*/

    /*@ requires dbManager != null; @*/
    public AgentController(DatabaseManager dbManager) {
        this.advisoryRepo = new AdvisoryRepository(dbManager.getConnection());
        this.apiClient = new NvdApiClient();
        this.parserFactory = new AdvisoryParserFactory();
        this.agentFacade = new AgentFacade(new GeminiLLMClient());
        this.commandManager = new CommandManager();
        this.observers = new ArrayList<>();
    }

    /**
     * Registers a new observer (like the OrionGUI) to listen for security events.
     */
    /*@ requires observer != null; @*/
    public void addObserver(SecurityObserver observer) {
        this.observers.add(observer);
    }

    /**
     * Broadcasts an event to all registered listeners.
     */
    /*@ requires eventType != null && eventType.length() > 0; @*/
    private void notifyObservers(String eventType, Object data) {
        for (SecurityObserver observer : observers) {
            observer.onSecurityEvent(eventType, data);
        }
    }

    /*@ requires source != null && source.length() > 0; @*/
    public void syncFeeds(String source) {
        try {
            // Notify GUI that sync has started
            notifyObservers("SYNC_STARTED", source);
            
            String rawData = apiClient.fetchRawAdvisories();
            AdvisoryParser parser = parserFactory.createParser("JSON");
            List<ThreatAdvisory> advisories = parser.parse(rawData);
            advisoryRepo.saveAll(advisories);
            
            // Notify GUI that sync was completely successful, passing the count
            notifyObservers("SYNC_COMPLETE", advisories.size());
            
        } catch (Exception e) {
            // Notify GUI of the error so it can show a popup, rather than crashing
            notifyObservers("SYNC_ERROR", e.getMessage());
        }
    }

    /*@ requires query != null && query.length() > 0; @*/
    public String handleNaturalQuery(String query) {
        return agentFacade.processGoal(query);
    }
    
    /*@ requires cmd != null; @*/
    public boolean executeCommand(SecurityCommand cmd) {
        boolean success = commandManager.invoke(cmd);
        if (success) {
            notifyObservers("COMMAND_EXECUTED", cmd.getDescription());
        }
        return success;
    }
    
    public boolean undoLastCommand() {
        boolean success = commandManager.undoLast();
        if (success) {
            notifyObservers("COMMAND_UNDONE", "Previous action rolled back.");
        }
        return success;
    }
    /**
     * Compiles and exports threat briefings to the local disk.
     * Maps to Feature F07 and Use Case UC-06.
     * 
     * @param advisories The list of advisories to export.
     * @param destinationPath The local path where the file should be saved.
     */
    /*@ 
      @ requires advisories != null && destinationPath != null;
      @*/
    public boolean exportThreatBriefing(List<ThreatAdvisory> advisories, String destinationPath) {
        ca.yorku.eecs3311.orion.util.ReportExporter exporter = new ca.yorku.eecs3311.orion.util.ReportExporter();
        boolean success = exporter.exportToMarkdown(advisories, destinationPath);
        if (success) {
            notifyObservers("REPORT_EXPORTED", destinationPath);
        }
        return success;
    }
    /**
     * Extracts structured Indicators of Compromise from unstructured threat text.
     * Maps to Feature F06 and Use Case UC-05.
     * 
     * @param rawText Unstructured threat report text.
     * @return A list of extracted and deduplicated IoCs.
     */
    /*@ 
      @ requires rawText != null;
      @ ensures \result != null;
      @*/
    public List<String> extractIocsFromText(String rawText) {
        ca.yorku.eecs3311.orion.util.IocExtractor extractor = new ca.yorku.eecs3311.orion.util.IocExtractor();
        List<String> results = extractor.extractIocs(rawText);
        notifyObservers("IOCS_EXTRACTED", results.size());
        return results;
    }
    /**
     * Retrieves an advisory by ID and requests an AI-generated executive summary.
     * Maps to Feature F02 and Sequence Diagram SD-01.
     * 
     * @param cveId The CVE identifier.
     * @return The executive summary.
     */
    /*@ 
      @ requires cveId != null && cveId.length() > 0;
      @ ensures \result != null;
      @*/
    public String summarizeAdvisory(String cveId) {
        ThreatAdvisory advisory = advisoryRepo.findById(cveId);
        if (advisory == null) {
            return "Error: Advisory with ID " + cveId + " not found in local database.";
        }
        
        String summary = agentFacade.summarizeAdvisory(advisory);
        notifyObservers("SUMMARY_GENERATED", cveId);
        return summary;
    }
}