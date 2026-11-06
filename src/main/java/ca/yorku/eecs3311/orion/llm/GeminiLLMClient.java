package ca.yorku.eecs3311.orion.llm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Concrete implementation of LLMClient for Google Gemini 3.8 Flash.
 * Includes automatic retry logic, strict timeouts, and safe environment variable loading.
 */
public class GeminiLLMClient implements LLMClient {

    private String apiKey;
    private HttpClient httpClient;
    private ObjectMapper objectMapper;
    
    // Using the upgraded 3.8-flash endpoint
    private static final String API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=";

    public GeminiLLMClient() {
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
        
        // Safely parse the .env file natively without requiring extra Maven dependencies
        String envKey = System.getenv("GEMINI_API_KEY");
        if (envKey == null || envKey.isEmpty()) {
            try {
                java.util.List<String> lines = java.nio.file.Files.readAllLines(java.nio.file.Paths.get(".env"));
                for (String line : lines) {
                    if (line.startsWith("GEMINI_API_KEY=")) {
                        envKey = line.substring("GEMINI_API_KEY=".length()).trim();
                        break;
                    }
                }
            } catch (Exception e) {
                // File not found or unreadable, handled below
            }
        }
        
        // The .trim() ensures hidden spaces or carriage returns don't break the API URL
        this.apiKey = (envKey != null && !envKey.isEmpty()) ? envKey.trim() : "MISSING_API_KEY";
    }

    @Override
    public String generate(String prompt) {
        if ("MISSING_API_KEY".equals(this.apiKey)) {
            return "[Offline Simulation] Gemini API Key missing. Please check your .env file.";
        }

        try {
            String requestBody = buildRequestBody(prompt);
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_BASE_URL + this.apiKey))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(15)) // CRITICAL: Prevents the UI from silently hanging forever
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            int maxRetries = 3;
            for (int i = 0; i < maxRetries; i++) {
                try {
                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                    if (response.statusCode() == 200) {
                        return parseResponseBody(response.body());
                    } else if (response.statusCode() == 503 || response.statusCode() == 429) {
                        if (i == maxRetries - 1) {
                            return "LLM API Error: Google's Gemini servers are currently overloaded (HTTP " + response.statusCode() + "). Please try again later.";
                        }
                        Thread.sleep(2000 * (i + 1)); // Backoff and retry
                    } else {
                        return "LLM API Error (HTTP " + response.statusCode() + "): " + response.body();
                    }
                } catch (java.net.http.HttpTimeoutException e) {
                    if (i == maxRetries - 1) {
                        return "LLM API Error: The connection to Google timed out. The server is likely overloaded.";
                    }
                }
            }
        } catch (Exception e) {
            return "Critical LLM Client Exception: " + e.getMessage();
        }
        
        return "Warning: AI request failed to complete.";
    }

    private String buildRequestBody(String prompt) throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        ArrayNode contents = root.putArray("contents");
        ObjectNode content = contents.addObject();
        ArrayNode parts = content.putArray("parts");
        ObjectNode part = parts.addObject();
        
        part.put("text", prompt);
        
        return objectMapper.writeValueAsString(root);
    }

    private String parseResponseBody(String jsonResponse) throws Exception {
        JsonNode root = objectMapper.readTree(jsonResponse);
        JsonNode candidates = root.path("candidates");
        
        if (candidates.isArray() && !candidates.isEmpty()) {
            JsonNode firstCandidate = candidates.get(0);
            JsonNode parts = firstCandidate.path("content").path("parts");
            
            if (parts.isArray() && !parts.isEmpty()) {
                return parts.get(0).path("text").asText();
            }
        }
        
        // Handle Google blocking the request due to content safety ratings
        if (root.has("promptFeedback")) {
             return "AI Warning: Request blocked by Google safety filters. Ensure the prompt does not violate API policies.";
        }
        
        return "Warning: AI returned an unparseable response. Check your API version.";
    }
}