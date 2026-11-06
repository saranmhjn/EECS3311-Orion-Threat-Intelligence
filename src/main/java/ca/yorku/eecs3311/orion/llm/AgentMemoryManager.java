package ca.yorku.eecs3311.orion.llm;

import java.util.ArrayList;
import java.util.List;

/**
 * Manages the conversation context and session memory for the AI agent.
 * Fulfills the AgentMemoryManager component in the Stage 1 UML diagram.
 */
public class AgentMemoryManager {
    
    // The buffer storing the history of the current interaction session
    private List<String> conversationBuffer;

    /*@ public invariant conversationBuffer != null; @*/

    /*@ ensures this.conversationBuffer != null; @*/
    public AgentMemoryManager() {
        this.conversationBuffer = new ArrayList<>();
    }

    /**
     * Appends a new message to the active session context.
     */
    /*@ 
      @ requires message != null; 
      @ ensures conversationBuffer.size() == \old(conversationBuffer.size()) + 1;
      @*/
    public void appendContext(String message) {
        this.conversationBuffer.add(message);
    }

    /**
     * Retrieves the entire conversation history as a single formatted string.
     */
    /*@ ensures \result != null; @*/
    public String retrieveContext() {
        return String.join("\n", this.conversationBuffer);
    }

    /**
     * Wipes the current session memory.
     */
    /*@ ensures conversationBuffer.isEmpty(); @*/
    public void clear() {
        this.conversationBuffer.clear();
    }
}