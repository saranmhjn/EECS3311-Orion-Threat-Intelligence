package ca.yorku.eecs3311.orion.repository;

import ca.yorku.eecs3311.orion.model.AdvisoryFilter;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles all database persistence and retrieval for ThreatAdvisories.
 * Implements real SQL queries to support Feature F08 (Historical Threat Repository Search).
 */
public class AdvisoryRepository {

    private Connection dbConnection;

    /*@ public invariant dbConnection != null; @*/

    /*@ 
      @ requires dbConnection != null;
      @ ensures this.dbConnection == dbConnection;
      @*/
    public AdvisoryRepository(Connection dbConnection) {
        this.dbConnection = dbConnection;
        createTableIfNotExists();
    }

    /**
     * Ensures the SQLite table exists on startup.
     */
    private void createTableIfNotExists() {
        String createTableSQL = "CREATE TABLE IF NOT EXISTS threat_advisories (" +
                "id TEXT PRIMARY KEY, " +
                "title TEXT, " +
                "severity TEXT, " +
                "description TEXT)";
        try (PreparedStatement pstmt = dbConnection.prepareStatement(createTableSQL)) {
            pstmt.execute();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Persists a list of threat advisories into the database.
     */
    /*@ requires advisories != null; @*/
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
        String querySQL = "SELECT id, title, severity, description FROM threat_advisories WHERE id = ?";
        try (PreparedStatement pstmt = dbConnection.prepareStatement(querySQL)) {
            pstmt.setString(1, cveId);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return new ThreatAdvisory(
                    rs.getString("id"),
                    rs.getString("title"),
                    rs.getString("severity"),
                    rs.getString("description")
                );
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Finds a list of advisories matching specific filter criteria.
     * Implements Feature F08 (Filter Historical Advisory Repository).
     */
    /*@ 
      @ requires filter != null;
      @ ensures \result != null;
      @*/
    public List<ThreatAdvisory> findByCriteria(AdvisoryFilter filter) {
        List<ThreatAdvisory> results = new ArrayList<>();
        StringBuilder querySQL = new StringBuilder("SELECT id, title, severity, description FROM threat_advisories WHERE 1=1");
        
        if (filter.getSeverityThreshold() != null && !filter.getSeverityThreshold().isEmpty()) {
            querySQL.append(" AND severity = ?");
        }

        try (PreparedStatement pstmt = dbConnection.prepareStatement(querySQL.toString())) {
            if (filter.getSeverityThreshold() != null && !filter.getSeverityThreshold().isEmpty()) {
                pstmt.setString(1, filter.getSeverityThreshold());
            }
            
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                results.add(new ThreatAdvisory(
                    rs.getString("id"),
                    rs.getString("title"),
                    rs.getString("severity"),
                    rs.getString("description")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        
        return results;
    }
}