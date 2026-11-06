package ca.yorku.eecs3311.orion.llm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Concrete implementation of LLMClient for Google Gemini 2.5 Flash.
 * Handles API authentication, JSON payload formatting, and live HTTP connections.
 */
public class GeminiLLMClient implements LLMClient {

    private String apiKey;
    private HttpClient httpClient;
    private ObjectMapper objectMapper;
    
    private static final String API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=";

    /*@ public invariant apiKey != null; @*/
    /*@ public invariant httpClient != null; @*/
    /*@ public invariant objectMapper != null; @*/

    /*@
      @ requires true;
      @ ensures this.httpClient != null;
      @ ensures this.apiKey != null;
      @ ensures this.objectMapper != null;
      @*/
    public GeminiLLMClient() {
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
        
        String envKey = System.getenv("GEMINI_API_KEY");
        this.apiKey = (envKey != null && !envKey.isEmpty()) ? envKey : "MISSING_API_KEY";
    }

    @Override
    public String generate(String prompt) throws Exception {
        if ("MISSING_API_KEY".equals(this.apiKey)) {
            // Fails gracefully if the environment variable isn't set yet
            return "[Offline Simulation] Gemini API Key missing. Prompt received: " + prompt;
        }

        // 1. Build the strictly formatted JSON request body required by Google
        String requestBody = buildRequestBody(prompt);

        // 2. Construct the HTTP POST request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_BASE_URL + this.apiKey))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        // 3. Send the request and capture the response
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new Exception("LLM API Error (HTTP " + response.statusCode() + "): " + response.body());
        }

        // 4. Parse the AI's generated text from the deep JSON response tree
        return parseResponseBody(response.body());
    }

    /**
     * Constructs the {"contents": [{"parts":[{"text": "prompt"}]}]} JSON structure.
     */
    /*@ 
      @ requires prompt != null;
      @ ensures \result != null && \result.length() > 0;
      @*/
    private String buildRequestBody(String prompt) throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        ArrayNode contents = root.putArray("contents");
        ObjectNode content = contents.addObject();
        ArrayNode parts = content.putArray("parts");
        ObjectNode part = parts.addObject();
        
        part.put("text", prompt);
        
        return objectMapper.writeValueAsString(root);
    }

    /**
     * Extracts the finalized text string from Gemini's nested JSON response.
     */
    /*@
      @ requires jsonResponse != null && jsonResponse.length() > 0;
      @ ensures \result != null;
      @*/
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
        return "Warning: AI returned an empty or unparseable response.";
    }
}