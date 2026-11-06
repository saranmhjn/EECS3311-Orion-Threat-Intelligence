package ca.yorku.eecs3311.orion.repository;

import ca.yorku.eecs3311.orion.model.AdvisoryFilter;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;

/**
 * Handles all database persistence and retrieval for ThreatAdvisories.
 * Maintains the exact method signatures defined in the Stage 1 UML diagram.
 */
public class AdvisoryRepository {

    private Connection dbConnection;

    /*@ public invariant dbConnection != null; @*/

    /**
     * Initializes the repository with an active database connection.
     * 
     * @param dbConnection The active SQLite connection.
     */
    /*@
      @ requires dbConnection != null;
      @ ensures this.dbConnection == dbConnection;
      @*/
    public AdvisoryRepository(Connection dbConnection) {
        this.dbConnection = dbConnection;
    }

    /**
     * Persists a list of threat advisories into the database.
     * 
     * @param advisories The list of ThreatAdvisory objects to save.
     */
    /*@
      @ requires advisories != null;
      @*/
    public void saveAll(List<ThreatAdvisory> advisories) {
        String insertSQL = "INSERT OR REPLACE INTO threat_advisories (id, title, severity, description) VALUES (?, ?, ?, ?)";
        
        try (PreparedStatement pstmt = dbConnection.prepareStatement(insertSQL)) {
            for (ThreatAdvisory advisory : advisories) {
                pstmt.setString(1, advisory.getId());
                pstmt.setString(2, advisory.getTitle());
                pstmt.setString(3, advisory.getSeverity());
                pstmt.setString(4, advisory.getDescription());
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Finds a single threat advisory by its unique CVE ID.
     */
    /*@
      @ requires cveId != null && cveId.length() > 0;
      @*/
    public ThreatAdvisory findById(String cveId) {
        // Implementation stub for findById (to be expanded in future commits)
        return new ThreatAdvisory(); 
    }

    /**
     * Finds a list of advisories matching specific filter criteria.
     */
    /*@
      @ requires filter != null;
      @ ensures \result != null;
      @*/
    public List<ThreatAdvisory> findByCriteria(AdvisoryFilter filter) {
        // Implementation stub for findByCriteria (to be expanded in future commits)
        return java.util.Collections.emptyList();
    }
}