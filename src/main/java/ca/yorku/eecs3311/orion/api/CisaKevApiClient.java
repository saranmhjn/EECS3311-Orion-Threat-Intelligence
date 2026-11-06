package ca.yorku.eecs3311.orion.api;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * API client responsible for fetching CISA Known Exploited Vulnerabilities (KEV).
 */
public class CisaKevApiClient {

    private static final String API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private final HttpClient httpClient;

    public CisaKevApiClient() {
        this.httpClient = HttpClient.newHttpClient();
    }

    public String fetchRawAdvisories() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            return response.body();
        } else {
            throw new RuntimeException("Failed to fetch CISA KEV feed: HTTP " + response.statusCode());
        }
    }
}