package ca.yorku.eecs3311.orion.api;

/**
 * Factory class responsible for instantiating the correct AdvisoryParser implementation.
 * Fulfills the Factory Method Pattern requirement from the Stage 1 UML diagram.
 */
public class AdvisoryParserFactory {
    
    public AdvisoryParser createParser(String feedType) {
        if ("NIST".equalsIgnoreCase(feedType) || "JSON".equalsIgnoreCase(feedType)) {
            return new NistNvdParser();
        } else if ("CISA".equalsIgnoreCase(feedType)) {
            return new CisaKevParser();
        }
        return new CisaKevParser(); // Default fallback
    }
}