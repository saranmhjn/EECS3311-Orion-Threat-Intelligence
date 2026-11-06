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
 * Concrete implementation of LLMClient for Groq's LLaMA 3 70B model.
 * Serves as the high-speed, reliable fallback.
 */
public class GroqLLMClient implements LLMClient {

    private String apiKey;
    private HttpClient httpClient;
    private ObjectMapper objectMapper;
    
    // Groq's OpenAI-compatible endpoint
    private static final String API_BASE_URL = "https://api.groq.com/openai/v1/chat/completions";

    public GroqLLMClient() {
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
        
        // Safely parse the .env file natively
        String envKey = System.getenv("GROQ_API_KEY");
        if (envKey == null || envKey.isEmpty()) {
            try {
                java.util.List<String> lines = java.nio.file.Files.readAllLines(java.nio.file.Paths.get(".env"));
                for (String line : lines) {
                    if (line.startsWith("GROQ_API_KEY=")) {
                        envKey = line.substring("GROQ_API_KEY=".length()).trim();
                        break;
                    }
                }
            } catch (Exception e) {
                // File not found, handled below
            }
        }
        
        this.apiKey = (envKey != null && !envKey.isEmpty()) ? envKey.trim() : "MISSING_API_KEY";
    }

    @Override
    public String generate(String prompt) {
        if ("MISSING_API_KEY".equals(this.apiKey)) {
            return "[Offline Simulation] Groq API Key missing. Please check your .env file.";
        }

        try {
            String requestBody = buildRequestBody(prompt);
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_BASE_URL))
                    .header("Authorization", "Bearer " + this.apiKey)
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(15)) // Prevents infinite UI hangs
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            int maxRetries = 3;
            for (int i = 0; i < maxRetries; i++) {
                try {
                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                    if (response.statusCode() == 200) {
                        return parseResponseBody(response.body());
                    } else if (response.statusCode() == 429 || response.statusCode() == 503) {
                        if (i == maxRetries - 1) {
                            return "LLM API Error: Groq servers overloaded (HTTP " + response.statusCode() + ").";
                        }
                        Thread.sleep(1000 * (i + 1));
                    } else {
                        return "LLM API Error (HTTP " + response.statusCode() + "): " + response.body();
                    }
                } catch (java.net.http.HttpTimeoutException e) {
                    if (i == maxRetries - 1) {
                        return "LLM API Error: The connection to Groq timed out.";
                    }
                }
            }
        } catch (Exception e) {
            return "Critical LLM Client Exception: " + e.getMessage();
        }
        return "Warning: AI request failed.";
    }

    private String buildRequestBody(String prompt) throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        
        // Target the specific LLaMA 3 model from your Stage 1 architecture
        root.put("model", "openai/gpt-oss-120b"); 
        
        ArrayNode messages = root.putArray("messages");
        ObjectNode message = messages.addObject();
        message.put("role", "user");
        message.put("content", prompt);
        
        return objectMapper.writeValueAsString(root);
    }

    private String parseResponseBody(String jsonResponse) throws Exception {
        JsonNode root = objectMapper.readTree(jsonResponse);
        JsonNode choices = root.path("choices");
        
        if (choices.isArray() && !choices.isEmpty()) {
            return choices.get(0).path("message").path("content").asText();
        }
        return "Warning: AI returned an unparseable response.";
    }
}