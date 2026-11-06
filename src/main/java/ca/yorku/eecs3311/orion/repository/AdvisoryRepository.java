package ca.yorku.eecs3311.orion.repository;

import ca.yorku.eecs3311.orion.model.AdvisoryFilter;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

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

    private void createTableIfNotExists() {
        String createTableSQL = "CREATE TABLE IF NOT EXISTS threat_advisories (" +
                "id TEXT PRIMARY KEY, " +
                "title TEXT, " +
                "severity TEXT, " +
                "vendor TEXT, " +
                "product TEXT, " +
                "threat_type TEXT, " +
                "description TEXT, " +
                "published_date TEXT" +
                ")";
        try (PreparedStatement pstmt = dbConnection.prepareStatement(createTableSQL)) {
            pstmt.execute();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /*@ requires advisories != null; @*/
    public void saveAll(List<ThreatAdvisory> advisories) {
        String insertSQL = "INSERT OR REPLACE INTO threat_advisories " +
                   "(id, title, severity, vendor, product, threat_type, description, published_date) " +
                   "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"; // <-- Must be exactly 8 question marks
        
        try {
            dbConnection.setAutoCommit(false); 
            try (PreparedStatement pstmt = dbConnection.prepareStatement(insertSQL)) {
                for (ThreatAdvisory advisory : advisories) {
                    pstmt.setString(1, advisory.getId());
                    pstmt.setString(2, advisory.getTitle());
                    pstmt.setString(3, advisory.getSeverity());
                    pstmt.setString(4, advisory.getVendor());
                    pstmt.setString(5, advisory.getProduct());
                    pstmt.setString(6, advisory.getThreatType());
                    pstmt.setString(7, advisory.getDescription());
                    pstmt.setString(8, advisory.getPublishedDate());
                    pstmt.addBatch();
                }
                pstmt.executeBatch();
            }
            dbConnection.commit(); 
            dbConnection.setAutoCommit(true);
        } catch (SQLException e) {
            try {
                dbConnection.rollback();
                dbConnection.setAutoCommit(true);
            } catch (SQLException rollbackEx) {
                rollbackEx.printStackTrace();
            }
            e.printStackTrace();
        }
    }

    /*@ 
      @ requires cveId != null && cveId.length() > 0;
      @*/
    public ThreatAdvisory findById(String id) {
        // Added published_date to the SELECT statement
        String querySQL = "SELECT id, title, severity, vendor, product, threat_type, description, published_date FROM threat_advisories WHERE id = ?";
        
        try (PreparedStatement pstmt = dbConnection.prepareStatement(querySQL)) {
            pstmt.setString(1, id);
            ResultSet rs = pstmt.executeQuery();
            
            if (rs.next()) {
                return new ThreatAdvisory(
                    rs.getString("id"),
                    rs.getString("title"),
                    rs.getString("severity"),
                    rs.getString("vendor"),
                    rs.getString("product"),
                    rs.getString("threat_type"),
                    rs.getString("description"),
                    rs.getString("published_date") // Ensure this 8th parameter is passed
                );
            }
        } catch (SQLException e) {
            System.err.println("[Database Error] Failed to find advisory by ID: " + e.getMessage());
        }
        return null;
    }

    /*@ ensures \result != null; @*/
   public List<ThreatAdvisory> findAll() {
        List<ThreatAdvisory> results = new ArrayList<>();
        // Added ORDER BY id DESC so recent years appear at the top
        String querySQL = "SELECT id, title, severity, vendor, product, threat_type, description, published_date FROM threat_advisories ORDER BY id DESC";
        
        try (PreparedStatement pstmt = dbConnection.prepareStatement(querySQL)) {
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                results.add(new ThreatAdvisory(
                    rs.getString("id"),
                    rs.getString("title"),
                    rs.getString("severity"),
                    rs.getString("vendor"),
                    rs.getString("product"),
                    rs.getString("threat_type"),
                    rs.getString("description"),
                    rs.getString("published_date")
                ));
            }
        } catch (SQLException e) {
            System.err.println("[Database Error] Failed to fetch advisories: " + e.getMessage());
            e.printStackTrace();
        }
        return results;
    }

    /*@ 
      @ requires filter != null;
      @ ensures \result != null;
      @*/
    public List<ThreatAdvisory> findByCriteria(AdvisoryFilter filter) {
        List<ThreatAdvisory> results = new ArrayList<>();
        StringBuilder querySQL = new StringBuilder("SELECT id, title, severity, vendor, product, threat_type, description FROM threat_advisories WHERE 1=1");
        
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
                    rs.getString("vendor"),
                    rs.getString("product"),
                    rs.getString("threat_type"),
                    rs.getString("description"),
                    rs.getString("published_date")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        
        return results;
    }
}