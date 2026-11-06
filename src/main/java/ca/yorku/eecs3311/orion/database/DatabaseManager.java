package ca.yorku.eecs3311.orion.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Manages the SQLite database connection and initialization for Orion Threat Intelligence.
 * Ensures the local schema is properly configured before data ingestion.
 */
public class DatabaseManager {

    // The JDBC connection string pointing to the local SQLite database file
    private static final String DB_URL = "jdbc:sqlite:orion.db";
    
    // The active database connection instance
    private Connection connection;

    /*@ 
      @ public invariant DB_URL != null;
      @ public invariant connection != null ==> !connection.isClosed();
      @*/

    /**
     * Initializes the database connection and builds the required tables.
     * 
     * @throws SQLException if a database access error occurs.
     */
    /*@
      @ requires true;
      @ ensures this.connection != null;
      @ ensures !this.connection.isClosed();
      @*/
    public DatabaseManager() throws SQLException {
        this.connection = DriverManager.getConnection(DB_URL);
        initializeTables();
    }

    /**
     * Creates the threat_advisories table if it does not already exist.
     * The schema maps directly to the ThreatAdvisory domain model fields.
     * 
     * @throws SQLException if table creation fails.
     */
    /*@
      @ requires this.connection != null;
      @ requires !this.connection.isClosed();
      @*/
    private void initializeTables() throws SQLException {
        String createTableSQL = "CREATE TABLE IF NOT EXISTS threat_advisories ("
                + "id TEXT PRIMARY KEY, "
                + "title TEXT NOT NULL, "
                + "severity TEXT, "
                + "vendor TEXT, "
                + "product TEXT, "
                + "threat_type TEXT, "
                + "description TEXT, "
                + "published_date TEXT"
                + ");";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createTableSQL);
        }
    }

    /**
     * Retrieves the active database connection.
     * 
     * @return The active Connection object.
     */
    /*@
      @ requires this.connection != null;
      @ ensures \result == this.connection;
      @*/
    public Connection getConnection() {
        return connection;
    }
}