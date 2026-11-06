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
        // We can easily add "XML" here in the future for CISA KEV
        if ("JSON".equalsIgnoreCase(format)) {
            return new NvdJsonParser();
        }
        // Default fallback
        return new NvdJsonParser();
    }
}