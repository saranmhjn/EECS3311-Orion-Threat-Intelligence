package ca.yorku.eecs3311.orion.tool;

import java.util.HashMap;
import java.util.Map;

/**
 * Context class for the Strategy Pattern.
 * Registers and dynamically dispatches execution requests to specific tools.
 */
public class ToolManager {
    
    private Map<String, Tool> tools;

    /*@ public invariant tools != null; @*/

    /*@ ensures this.tools != null; @*/
    public ToolManager() {
        this.tools = new HashMap<>();
    }

    /**
     * Registers a new tool into the agent's available toolkit.
     */
    /*@ requires tool != null; @*/
    public void registerTool(Tool tool) {
        tools.put(tool.getName(), tool);
    }

    /**
     * Dynamically routes an execution request to the correct tool.
     */
    /*@ 
      @ requires name != null && args != null; 
      @*/
    public Object executeTool(String name, Map<String, Object> args) throws Exception {
        Tool tool = tools.get(name);
        if (tool != null) {
            return tool.execute(args);
        }
        throw new IllegalArgumentException("Tool not registered: " + name);
    }
}