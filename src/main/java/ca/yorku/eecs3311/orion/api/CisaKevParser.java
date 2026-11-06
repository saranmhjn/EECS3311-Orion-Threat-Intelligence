package ca.yorku.eecs3311.orion.api;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

public class CisaKevParser implements AdvisoryParser {

    private final ObjectMapper objectMapper;

    public CisaKevParser() {
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public List<ThreatAdvisory> parse(String rawData) throws Exception {
        List<ThreatAdvisory> advisories = new ArrayList<>();
        JsonNode root = objectMapper.readTree(rawData);
        JsonNode vulnerabilities = root.path("vulnerabilities");

        if (vulnerabilities.isArray()) {
            // Read backwards to grab the 15 most recently added threats
            int count = 0;
            for (int i = vulnerabilities.size() - 1; i >= 0 && count < 100; i--) {
                JsonNode vuln = vulnerabilities.get(i);
                
                String id = vuln.path("cveID").asText("UNKNOWN");
                String title = vuln.path("vulnerabilityName").asText("Unknown Threat");
                
                // CISA KEV doesn't use CVSS scores; presence on this list implies critical active exploitation
                String severity = "CRITICAL (KEV)"; 
                
                String description = vuln.path("shortDescription").asText() + 
                                     " Required Action: " + vuln.path("requiredAction").asText();
                
                advisories.add(new ThreatAdvisory(id, title, severity, description));
                count++;
            }
        }
        return advisories;
    }
}