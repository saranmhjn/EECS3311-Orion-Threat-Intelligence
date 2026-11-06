package ca.yorku.eecs3311.orion.tool;

import java.util.Map;

/**
 * Interface defining a deterministic utility that the AI agent can execute.
 * Fulfills the Strategy Pattern requirement in the Stage 1 UML diagram.
 */
public interface Tool {
    
    /**
     * Retrieves the unique string identifier for this tool.
     */
    /*@ ensures \result != null && \result.length() > 0; @*/
    String getName();

    /**
     * Executes the tool's specific logic with the provided arguments.
     * 
     * @param args A map of arguments required by the specific tool.
     * @return The resulting parsed data or confirmation.
     * @throws Exception if tool execution fails.
     */
    /*@ requires args != null; @*/
    Object execute(Map<String, Object> args) throws Exception;
}