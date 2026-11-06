package ca.yorku.eecs3311.orion.controller;

import ca.yorku.eecs3311.orion.api.AdvisoryParser;
import ca.yorku.eecs3311.orion.api.AdvisoryParserFactory;
import ca.yorku.eecs3311.orion.api.NvdApiClient;
import ca.yorku.eecs3311.orion.database.DatabaseManager;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import ca.yorku.eecs3311.orion.repository.AdvisoryRepository;

import java.util.List;

/**
 * The central deterministic orchestrator for the Orion Threat Intelligence system.
 * Coordinates boundary inputs with the local database and external tools.
 */
public class AgentController {

    private AdvisoryRepository advisoryRepo;
    private NvdApiClient apiClient;
    private AdvisoryParserFactory parserFactory;

    /*@
      @ public invariant advisoryRepo != null;
      @ public invariant apiClient != null;
      @ public invariant parserFactory != null;
      @*/

    /**
     * Initializes the controller and its dependent infrastructure.
     * 
     * @param dbManager The manager providing the active SQLite connection.
     */
    /*@ 
      @ requires dbManager != null;
      @ ensures this.advisoryRepo != null;
      @ ensures this.apiClient != null;
      @ ensures this.parserFactory != null;
      @*/
    public AgentController(DatabaseManager dbManager) {
        // Inject the active database connection into the repository
        this.advisoryRepo = new AdvisoryRepository(dbManager.getConnection());
        this.apiClient = new NvdApiClient();
        this.parserFactory = new AdvisoryParserFactory();
    }

    /**
     * Coordinates fetching, parsing, and storing external threat advisories.
     * Matches the expected workflow for Feature F01.
     * 
     * @param source The source to sync from (e.g., "NVD")
     */
    /*@
      @ requires source != null && source.length() > 0;
      @*/
    public void syncFeeds(String source) {
        try {
            // 1. Fetch raw data via HTTP GET request
            String rawData = apiClient.fetchRawAdvisories();
            
            // 2. Request the correct parser from the factory
            AdvisoryParser parser = parserFactory.createParser("JSON");
            
            // 3. Transform the raw payload into ThreatAdvisory domain objects
            List<ThreatAdvisory> advisories = parser.parse(rawData);
            
            // 4. Save directly to the local SQLite database
            advisoryRepo.saveAll(advisories);
            
            System.out.println("Successfully synchronized " + advisories.size() + " advisories from " + source);
            
        } catch (Exception e) {
            // Catches network or parsing exceptions and prevents application crashes
            System.err.println("Failed to sync feeds: " + e.getMessage());
        }
    }
}