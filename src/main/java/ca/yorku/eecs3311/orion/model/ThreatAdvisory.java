package ca.yorku.eecs3311.orion.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Domain model representing a single threat advisory.
 * Contains JML contracts to ensure data integrity for core fields.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ThreatAdvisory {
    
    private String id;
    private String title;
    private String severity;
    private String vendor;
    private String product;
    private String threatType; 
    private String description;
    private String publishedDate;

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
     */
    /*@
      @ requires id != null && id.length() > 0;
      @ ensures this.id == id;
      @ ensures this.title == title;
      @ ensures this.severity == severity;
      @ ensures this.vendor == vendor;
      @ ensures this.product == product;
      @ ensures this.threatType == threatType;
      @ ensures this.description == description;
      @ ensures this.publishedDate == publishedDate;
      @*/
    public ThreatAdvisory(String id, String title, String severity, String vendor, String product, String threatType, String description, String publishedDate) {
        this.id = id;
        this.title = title;
        this.severity = severity;
        this.vendor = vendor;
        this.product = product;
        this.threatType = threatType;
        this.description = description;
        this.publishedDate = publishedDate;
    }

    /*@ pure @*/
    public String getId() { return id; }
    /*@ pure @*/
    public String getTitle() { return title; }
    /*@ pure @*/
    public String getSeverity() { return severity; }
    /*@ pure @*/
    public String getVendor() { return vendor; }
    /*@ pure @*/
    public String getProduct() { return product; }
    /*@ pure @*/
    public String getThreatType() { return threatType; }
    /*@ pure @*/
    public String getDescription() { return description; }
    public String getPublishedDate() {
    return publishedDate != null ? publishedDate : "N/A";
}

    /*@
      @ requires id != null && id.length() > 0;
      @ ensures this.id == id;
      @*/
    public void setId(String id) { this.id = id; }
    /*@ ensures this.title == title; @*/
    public void setTitle(String title) { this.title = title; }
    /*@ ensures this.severity == severity; @*/
    public void setSeverity(String severity) { this.severity = severity; }
    /*@ ensures this.vendor == vendor; @*/
    public void setVendor(String vendor) { this.vendor = vendor; }
    /*@ ensures this.product == product; @*/
    public void setProduct(String product) { this.product = product; }
    /*@ ensures this.threatType == threatType; @*/
    public void setThreatType(String threatType) { this.threatType = threatType; }
    /*@ ensures this.description == description; @*/
    public void setDescription(String description) { this.description = description; }
    public void setPublishedDate(String publishedDate) {
    this.publishedDate = publishedDate;
}
}