package ca.yorku.eecs3311.orion.api;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

/**
 * Concrete implementation of AdvisoryParser for the National Vulnerability Database (NVD).
 * Transforms deeply nested JSON responses into clean ThreatAdvisory objects.
 */
public class NvdJsonParser implements AdvisoryParser {

    private final ObjectMapper objectMapper;

    /*@ public invariant objectMapper != null; @*/

    /*@
      @ requires true;
      @ ensures this.objectMapper != null;
      @*/
    public NvdJsonParser() {
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public List<ThreatAdvisory> parse(String rawData) throws Exception {
        List<ThreatAdvisory> advisories = new ArrayList<>();
        JsonNode root = objectMapper.readTree(rawData);
        JsonNode vulnerabilities = root.path("vulnerabilities");

        if (vulnerabilities.isArray()) {
            for (JsonNode vulnNode : vulnerabilities) {
                JsonNode cve = vulnNode.path("cve");
                String id = cve.path("id").asText("UNKNOWN_ID");
                
                String description = extractEnglishDescription(cve);
                String severity = extractSeverity(cve);
                String title = "Vulnerability " + id;
                
                advisories.add(new ThreatAdvisory(id, title, severity, description));
            }
        }
        return advisories;
    }

    /*@
      @ requires cveNode != null;
      @ ensures \result != null;
      @*/
    private String extractEnglishDescription(JsonNode cveNode) {
        JsonNode descriptions = cveNode.path("descriptions");
        if (descriptions.isArray() && !descriptions.isEmpty()) {
            for (JsonNode desc : descriptions) {
                if ("en".equals(desc.path("lang").asText())) {
                    return desc.path("value").asText();
                }
            }
        }
        return "No description available";
    }

    /*@
      @ requires cveNode != null;
      @ ensures \result != null;
      @*/
    private String extractSeverity(JsonNode cveNode) {
        JsonNode metrics = cveNode.path("metrics").path("cvssMetricV31");
        if (metrics.isArray() && !metrics.isEmpty()) {
            return metrics.get(0).path("cvssData").path("baseSeverity").asText("UNKNOWN");
        }
        return "UNKNOWN";
    }
}