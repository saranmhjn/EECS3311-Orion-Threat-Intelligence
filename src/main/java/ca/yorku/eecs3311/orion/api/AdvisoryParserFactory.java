package ca.yorku.eecs3311.orion.api;

/**
 * Factory class responsible for instantiating the correct AdvisoryParser implementation.
 * Fulfills the Factory Method Pattern requirement from the Stage 1 UML diagram.
 */
public class AdvisoryParserFactory {
    
    /**
     * Creates and returns a parser based on the requested data format.
     * 
     * @param format The data format (e.g., "JSON", "XML").
     * @return An implementation of AdvisoryParser.
     */
    /*@
      @ requires format != null;
      @ ensures \result != null;
      @*/
    public AdvisoryParser createParser(String format) {
        if ("CISA".equalsIgnoreCase(format)) {
            return new CisaKevParser();
        } else if ("JSON".equalsIgnoreCase(format)) {
            return new NvdJsonParser();
        }
        return new CisaKevParser(); // Default to the upgraded CISA feed
    }
}