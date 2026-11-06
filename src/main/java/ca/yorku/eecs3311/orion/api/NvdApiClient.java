package ca.yorku.eecs3311.orion.api;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Client responsible exclusively for executing HTTP network requests to the NVD API.
 * Delegates data parsing to the AdvisoryParser implementations.
 */
public class NvdApiClient {

    //CISA Known Exploited Vulnerabilities (KEV) feed URL
    private static final String API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private final HttpClient httpClient;

    /*@ public invariant httpClient != null; @*/
    /*@ public invariant API_URL != null && API_URL.length() > 0; @*/

    /*@
      @ requires true;
      @ ensures this.httpClient != null;
      @*/
    public NvdApiClient() {
        this.httpClient = HttpClient.newHttpClient();
    }

    /**
     * Fetches the raw JSON payload from the NVD API.
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
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}