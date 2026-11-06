package ca.yorku.eecs3311.orion.model;

/**
 * Filter object used by the AdvisoryRepository to perform multi-criteria searches.
 */
public class AdvisoryFilter {
    private String severityThreshold;

    /*@ ensures this.severityThreshold == null; @*/
    public AdvisoryFilter() {}

    /*@ pure @*/
    public String getSeverityThreshold() { return severityThreshold; }

    /*@ ensures this.severityThreshold == severityThreshold; @*/
    public void setSeverityThreshold(String severityThreshold) { 
        this.severityThreshold = severityThreshold; 
    }
}