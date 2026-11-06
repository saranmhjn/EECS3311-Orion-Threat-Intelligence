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
            for (int i = vulnerabilities.size() - 1; i >= 0; i--) {
                JsonNode vuln = vulnerabilities.get(i);

                String id = vuln.path("cveID").asText("UNKNOWN");
                String title = vuln.path("vulnerabilityName").asText("Unknown Threat");
                String vendor = vuln.path("vendorProject").asText("Unknown");
                String product = vuln.path("product").asText("Unknown");
                String ransomware = vuln.path("knownRansomwareCampaignUse").asText("Unknown");
                String notes = vuln.path("notes").asText("").toLowerCase();
                String descRaw = vuln.path("shortDescription").asText();
                String publishedDate = vuln.path("dateAdded").asText("N/A");

                String threatType;
                if (notes.contains("zero-day") || descRaw.toLowerCase().contains("zero-day")) {
                    threatType = "Zero-Day";
                } else if ("Known".equalsIgnoreCase(ransomware)) {
                    threatType = "Ransomware";
                } else {
                    threatType = "Active Exploit";
                }

                String severity = "CRITICAL";
                String description = descRaw + " | Action: " + vuln.path("requiredAction").asText();

                // FIX: Now using the new 7-argument constructor
                advisories.add(new ThreatAdvisory(id, title, severity, vendor, product, threatType, description, publishedDate)
                );
            }
        }
        return advisories;
    }
}