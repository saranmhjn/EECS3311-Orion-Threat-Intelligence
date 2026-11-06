package ca.yorku.eecs3311.orion.api;

import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

/**
 * Client responsible for fetching and parsing vulnerability data from the National Vulnerability Database (NVD) API.
 * Includes JML contracts to ensure network data is properly sanitized and parsed.
 */
public class NvdApiClient {

    // Target API endpoint (limited to 5 results for initial development and testing)
    private static final String API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=5";
    
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    /*@
      @ public invariant httpClient != null;
      @ public invariant objectMapper != null;
      @ public invariant API_URL != null && API_URL.length() > 0;
      @*/

    /**
     * Initializes the NVD API client with a standard Java HTTP client and Jackson JSON mapper.
     */
    /*@
      @ requires true;
      @ ensures this.httpClient != null;
      @ ensures this.objectMapper != null;
      @*/
    public NvdApiClient() {
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Fetches recent threat advisories from the NVD API and parses the JSON response into domain models.
     * 
     * @return A list of parsed ThreatAdvisory objects.
     * @throws Exception if the network request fails or JSON parsing encounters an error.
     */
    /*@
      @ requires true;
      @ ensures \result != null;
      @*/
    public List<ThreatAdvisory> fetchAdvisories() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        return parseJsonToAdvisories(response.body());
    }

    /**
     * Parses the deeply nested NVD JSON structure into our simplified ThreatAdvisory domain model.
     * Extracts the CVE ID, description (English), and base severity score.
     * 
     * @param jsonBody The raw JSON string returned by the API response.
     * @return A List of fully instantiated ThreatAdvisory objects.
     * @throws Exception if tree parsing fails.
     */
    /*@
      @ requires jsonBody != null && jsonBody.length() > 0;
      @ ensures \result != null;
      @*/
    private List<ThreatAdvisory> parseJsonToAdvisories(String jsonBody) throws Exception {
        List<ThreatAdvisory> advisories = new ArrayList<>();
        JsonNode root = objectMapper.readTree(jsonBody);
        JsonNode vulnerabilities = root.path("vulnerabilities");

        if (vulnerabilities.isArray()) {
            for (JsonNode vulnNode : vulnerabilities) {
                JsonNode cve = vulnNode.path("cve");
                
                String id = cve.path("id").asText("UNKNOWN_ID");
                
                // Navigate nested nodes to find the English description
                String description = "No description available";
                JsonNode descriptions = cve.path("descriptions");
                if (descriptions.isArray() && !descriptions.isEmpty()) {
                    for (JsonNode desc : descriptions) {
                        if ("en".equals(desc.path("lang").asText())) {
                            description = desc.path("value").asText();
                            break;
                        }
                    }
                }
                
                // Navigate nested nodes to find the CVSS v3.1 severity metric
                String severity = "UNKNOWN";
                JsonNode metrics = cve.path("metrics").path("cvssMetricV31");
                if (metrics.isArray() && !metrics.isEmpty()) {
                    severity = metrics.get(0).path("cvssData").path("baseSeverity").asText("UNKNOWN");
                }
                
                String title = "Vulnerability " + id;
                
                advisories.add(new ThreatAdvisory(id, title, severity, description));
            }
        }
        return advisories;
    }
}