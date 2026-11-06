package ca.yorku.eecs3311.orion.api;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

public class NvdJsonParser implements AdvisoryParser {

    private final ObjectMapper objectMapper;

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
                
                // Static defaults for NVD since it lacks CISA's explicit vendor/product keys
                String vendor = "NVD";
                String product = "Vulnerability";
                String threatType = "CVE";

                advisories.add(new ThreatAdvisory(id, title, severity, vendor, product, threatType, description));
            }
        }
        return advisories;
    }

    private String extractEnglishDescription(JsonNode cveNode) {
        JsonNode descriptions = cveNode.path("descriptions");
        if (descriptions.isArray()) {
            for (JsonNode desc : descriptions) {
                if ("en".equalsIgnoreCase(desc.path("lang").asText())) {
                    return desc.path("value").asText();
                }
            }
        }
        return "No description available.";
    }

    private String extractSeverity(JsonNode cveNode) {
        JsonNode metrics = cveNode.path("metrics");
        
        // Try modern CVSS v3.1 first
        if (metrics.hasNonNull("cvssMetricV31") && metrics.path("cvssMetricV31").isArray() && !metrics.path("cvssMetricV31").isEmpty()) {
            return metrics.path("cvssMetricV31").get(0).path("cvssData").path("baseSeverity").asText("UNKNOWN");
        }
        // Fallback to legacy CVSS v2 for older vulnerabilities
        if (metrics.hasNonNull("cvssMetricV2") && metrics.path("cvssMetricV2").isArray() && !metrics.path("cvssMetricV2").isEmpty()) {
            return metrics.path("cvssMetricV2").get(0).path("baseSeverity").asText("UNKNOWN");
        }
        
        return "UNKNOWN";
    }
}