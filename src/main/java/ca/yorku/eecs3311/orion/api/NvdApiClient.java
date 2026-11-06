package ca.yorku.eecs3311.orion.api;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * API client responsible for fetching raw JSON vulnerability feeds from the NIST NVD API v2.0.
 */
public class NvdApiClient {

    private static final String API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=500";
    private final HttpClient httpClient;

    /*@ public invariant httpClient != null; @*/

    /*@
      @ requires true;
      @ ensures this.httpClient != null;
      @*/
    public NvdApiClient() {
        this.httpClient = HttpClient.newHttpClient();
    }

    /**
     * Fetches the raw JSON payload from the NIST NVD API.
     * 
     * @return The raw JSON string returned by the API.
     * @throws Exception if the network request fails.
     */
    /*@
      @ requires true;
      @ ensures \result != null && \result.length() > 0;
      @*/
    public String fetchRawAdvisories() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            return response.body();
        } else {
            throw new RuntimeException("Failed to fetch NIST feed: HTTP " + response.statusCode());
        }
    }
}