package ca.yorku.eecs3311.orion.api;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;

public class NistNvdParser implements AdvisoryParser {

    private final ObjectMapper objectMapper;

    public NistNvdParser() {
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
                
                String vendor = "NIST NVD";
                String product = "Standard CVE";
                String threatType = "Vulnerability";

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
        // Fallback to legacy CVSS v2
        if (metrics.hasNonNull("cvssMetricV2") && metrics.path("cvssMetricV2").isArray() && !metrics.path("cvssMetricV2").isEmpty()) {
            double baseScore = metrics.path("cvssMetricV2").get(0).path("cvssData").path("baseScore").asDouble(0.0);
            if (baseScore >= 7.0) return "HIGH";
            if (baseScore >= 4.0) return "MEDIUM";
            if (baseScore > 0.0) return "LOW";
        }
        
        return "UNKNOWN";
    }
}