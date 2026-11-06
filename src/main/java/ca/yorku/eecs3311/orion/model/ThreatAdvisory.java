package ca.yorku.eecs3311.orion.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Domain model representing a single threat advisory from the NVD JSON feed.
 * Contains JML contracts to ensure data integrity for core fields.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ThreatAdvisory {
    
    private String id;
    private String title;
    private String severity;
    private String description;

    /*@ 
      @ public invariant id != null ==> id.length() > 0;
      @*/

    /**
     * Default constructor required by Jackson for JSON deserialization.
     */
    /*@
      @ requires true;
      @ ensures this.id == null;
      @*/
    public ThreatAdvisory() {
    }

    /**
     * Constructs a ThreatAdvisory with explicit fields.
     * 
     * @param id The unique identifier of the threat (e.g., CVE ID).
     * @param title The title or brief name of the threat.
     * @param severity The severity level (e.g., LOW, MEDIUM, HIGH, CRITICAL).
     * @param description A detailed explanation of the vulnerability.
     */
    /*@
      @ requires id != null && id.length() > 0;
      @ ensures this.id == id;
      @ ensures this.title == title;
      @ ensures this.severity == severity;
      @ ensures this.description == description;
      @*/
    public ThreatAdvisory(String id, String title, String severity, String description) {
        this.id = id;
        this.title = title;
        this.severity = severity;
        this.description = description;
    }

    /*@ pure @*/
    public String getId() { return id; }
    
    /*@ pure @*/
    public String getTitle() { return title; }
    
    /*@ pure @*/
    public String getSeverity() { return severity; }
    
    /*@ pure @*/
    public String getDescription() { return description; }

    /*@
      @ requires id != null && id.length() > 0;
      @ ensures this.id == id;
      @*/
    public void setId(String id) { this.id = id; }
    
    /*@ ensures this.title == title; @*/
    public void setTitle(String title) { this.title = title; }
    
    /*@ ensures this.severity == severity; @*/
    public void setSeverity(String severity) { this.severity = severity; }
    
    /*@ ensures this.description == description; @*/
    public void setDescription(String description) { this.description = description; }
}