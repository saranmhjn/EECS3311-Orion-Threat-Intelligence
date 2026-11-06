package ca.yorku.eecs3311.orion.api;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import java.util.List;

/**
 * Interface defining the contract for parsing raw threat intelligence feeds.
 * Maps directly to the AdvisoryParser component in the Stage 1 UML diagram.
 */
public interface AdvisoryParser {

    /**
     * Parses raw string data (JSON, XML, etc.) into a list of ThreatAdvisory domain models.
     * 
     * @param rawData The raw unparsed text from an external feed.
     * @return A list of instantiated ThreatAdvisory objects.
     * @throws Exception if parsing fails due to malformed data.
     */
    /*@
      @ requires rawData != null && rawData.length() > 0;
      @ ensures \result != null;
      @*/
    List<ThreatAdvisory> parse(String rawData) throws Exception;
}