package ca.yorku.eecs3311.orion.controller;

import ca.yorku.eecs3311.orion.api.AdvisoryParser;
import ca.yorku.eecs3311.orion.api.AdvisoryParserFactory;
import ca.yorku.eecs3311.orion.api.CisaKevApiClient;
import ca.yorku.eecs3311.orion.api.NvdApiClient;
import ca.yorku.eecs3311.orion.command.CommandManager;
import ca.yorku.eecs3311.orion.command.SecurityCommand;
import ca.yorku.eecs3311.orion.database.DatabaseManager;
import ca.yorku.eecs3311.orion.llm.AgentFacade;
import ca.yorku.eecs3311.orion.model.AdvisoryFilter;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import ca.yorku.eecs3311.orion.repository.AdvisoryRepository;
import ca.yorku.eecs3311.orion.observer.SecurityObserver;
import ca.yorku.eecs3311.orion.llm.GroqLLMClient;

import java.util.ArrayList;
import java.util.List;

/**
 * The central deterministic orchestrator for the Orion Threat Intelligence system.
 * Acts as the Subject in the Observer Pattern to notify boundary layers of state changes.
 */
@SuppressWarnings("unused")
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
        //this.agentFacade = new AgentFacade(new GeminiLLMClient());
        this.agentFacade = new AgentFacade(new GroqLLMClient());
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
   public void syncFeeds(String feedType) {
        try {
            // 1. Fetch raw data from the appropriate API client
            String rawData;
            if ("NIST".equalsIgnoreCase(feedType)) {
                NvdApiClient nvdClient = new NvdApiClient();
                rawData = nvdClient.fetchRawAdvisories(); // <-- Updated method name
            } else {
                CisaKevApiClient cisaClient = new CisaKevApiClient();
                rawData = cisaClient.fetchRawAdvisories(); // <-- Updated method name
            }

            // 2. Create the correct parser using the Factory Pattern
            AdvisoryParserFactory factory = new AdvisoryParserFactory();
            AdvisoryParser parser = factory.createParser(feedType);

            // 3. Parse records
            List<ThreatAdvisory> advisories = parser.parse(rawData);

            // 4. Save to SQLite repository
            advisoryRepo.saveAll(advisories);

            // 5. Notify UI observers (Observer Pattern)
            notifyObservers("SYNC_COMPLETE", advisories.size());

        } catch (Exception e) {
            e.printStackTrace();
            notifyObservers("SYNC_ERROR", "Sync failed: " + e.getMessage());
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
    /**
     * Evaluates an advisory's priority score against a target infrastructure profile.
     * Maps to Feature F09 and Sequence Diagram SD-03[cite: 10, 27].
     * 
     * @param cveId The CVE identifier.
     * @param techStack The local enterprise environment profile.
     * @return The customized priority assessment.
     */
    /*@ 
      @ requires cveId != null && techStack != null;
      @ ensures \result != null;
      @*/
    public String evaluateAdvisoryTriage(String cveId, String techStack) {
        ThreatAdvisory advisory = advisoryRepo.findById(cveId);
        if (advisory == null) {
            return "Error: Advisory with ID " + cveId + " not found in local database.";
        }
        
        String triageResult = agentFacade.evaluateDynamicTriage(advisory, techStack);
        notifyObservers("TRIAGE_EVALUATED", cveId);
        return triageResult;
    }

    /**
     * Generates a mitigation playbook for a stored threat advisory.
     * Maps to Feature F05 and Sequence Diagram SD-03[cite: 8, 27, 34].
     * 
     * @param cveId The CVE identifier.
     * @param environmentProfile The local enterprise infrastructure profile.
     * @return The generated mitigation playbook text.
     */
    /*@ 
      @ requires cveId != null && environmentProfile != null;
      @ ensures \result != null;
      @*/
    public String generateMitigationPlaybook(String cveId, String environmentProfile) {
        ThreatAdvisory advisory = advisoryRepo.findById(cveId);
        if (advisory == null) {
            return "Error: Advisory with ID " + cveId + " not found in local database.";
        }
        
        String playbook = agentFacade.planMitigation(advisory, environmentProfile);
        notifyObservers("MITIGATION_GENERATED", cveId);
        return playbook;
    }

    /**
     * Evaluates security control gaps for a stored threat advisory.
     * Maps to Feature F10 and Use Case UC-08[cite: 9, 21, 36].
     * 
     * @param cveId The CVE identifier.
     * @param activeControls List of configured enterprise security controls.
     * @return The structured gap analysis result.
     */
    /*@ 
      @ requires cveId != null && activeControls != null;
      @ ensures \result != null;
      @*/
    public String evaluateSecurityGaps(String cveId, List<String> activeControls) {
        ThreatAdvisory advisory = advisoryRepo.findById(cveId);
        if (advisory == null) {
            return "Error: Advisory with ID " + cveId + " not found in local database.";
        }
        
        String analysis = agentFacade.evaluateGaps(advisory, activeControls);
        notifyObservers("GAP_ANALYSIS_EVALUATED", cveId);
        return analysis;
    }

    /**
     * Correlates internal audit logs with threat indicators.
     * Maps to Feature F04 and Use Case UC-03[cite: 5, 17].
     * 
     * @param filePath Path to the local log file.
     * @return List of detected anomalies.
     */
    /*@ 
      @ requires filePath != null;
      @ ensures \result != null;
      @*/
    @SuppressWarnings("unchecked")
    public List<String> correlateLogs(String filePath) {
        try {
            java.util.Map<String, Object> args = new java.util.HashMap<>();
            args.put("filePath", filePath);
            
            List<String> anomalies = (List<String>) agentFacade.getToolManager().executeTool("LogParserTool", args);
            notifyObservers("LOGS_CORRELATED", anomalies.size());
            return anomalies;
        } catch (Exception e) {
            notifyObservers("LOG_ERROR", e.getMessage());
            return new java.util.ArrayList<>();
        }
    }
    /**
     * Retrieves all stored threat advisories from the local repository.
     * Used by boundary layers (GUI/CLI) to populate dashboards.
     * 
     * @return A list of all stored ThreatAdvisory objects.
     */
    /*@ ensures \result != null; @*/
    public List<ThreatAdvisory> getStoredAdvisories() {
        return advisoryRepo.findAll();
    }

    /*@ requires filter != null; @*/
    public List<ThreatAdvisory> searchAdvisories(AdvisoryFilter filter) {
        return advisoryRepo.findByCriteria(filter);
    }
}