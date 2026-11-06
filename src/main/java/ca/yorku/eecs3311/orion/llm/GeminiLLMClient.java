package ca.yorku.eecs3311.orion.llm;

import java.net.http.HttpClient;

/**
 * Concrete implementation of LLMClient for Google Gemini 2.5 Flash.
 * Handles API authentication and HTTP connections for AI reasoning tasks.
 */
public class GeminiLLMClient implements LLMClient {

    private String apiKey;
    private HttpClient httpClient;

    /*@ public invariant apiKey != null; @*/
    /*@ public invariant httpClient != null; @*/

    /**
     * Initializes the Gemini client with a standard Java HTTP client and environment API key.
     */
    /*@
      @ requires true;
      @ ensures this.httpClient != null;
      @ ensures this.apiKey != null;
      @*/
    public GeminiLLMClient() {
        this.httpClient = HttpClient.newHttpClient();
        
        // Pulls the API key from the .env file we configured in Commit 1.
        // Falls back to a placeholder to prevent null pointer crashes during early testing.
        String envKey = System.getenv("GEMINI_API_KEY");
        this.apiKey = (envKey != null && !envKey.isEmpty()) ? envKey : "MISSING_API_KEY";
    }

    @Override
    public String generate(String prompt) throws Exception {
        // For this structural commit, we establish the method signature and return a stub.
        // We will build the complex JSON payload construction and parsing in a future step.
        
        if ("MISSING_API_KEY".equals(this.apiKey)) {
            throw new Exception("Gemini API key is not configured in the environment.");
        }

        return "Simulated LLM Response for: " + prompt;
    }
}