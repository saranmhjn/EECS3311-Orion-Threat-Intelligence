package ca.yorku.eecs3311.orion.boundary;

import ca.yorku.eecs3311.orion.controller.AgentController;
import ca.yorku.eecs3311.orion.database.DatabaseManager;

/**
 * Command-Line Interface for Orion Threat Intelligence.
 * Serves as the primary entry point for headless execution of the AI agent.
 * Matches the OrionCLI specifications in the Stage 1 UML diagram.
 */
public class OrionCLI {

    private AgentController controller;

    /*@ public invariant controller != null; @*/

    /**
     * Initializes the CLI with the central orchestrator.
     */
    /*@ 
      @ requires controller != null;
      @ ensures this.controller == controller;
      @*/
    public OrionCLI(AgentController controller) {
        this.controller = controller;
    }

    /**
     * Parses the command-line arguments and routes them to the appropriate controller action.
     * 
     * @param args The array of command-line arguments passed by the user.
     */
    /*@ requires args != null; @*/
    public void parseAndExecute(String[] args) {
        if (args.length == 0) {
            System.out.println("==================================================");
            System.out.println("  Orion Threat Intelligence CLI (Stage 1 Build)   ");
            System.out.println("==================================================");
            System.out.println("Available Commands:");
            System.out.println("  sync               - Synchronize external threat feeds (NVD)");
            System.out.println("  query \"[text]\"     - Ask the AI agent about the threat landscape");
            System.out.println("==================================================");
            return;
        }

        String command = args[0].toLowerCase();

        switch (command) {
            case "sync":
                System.out.println("[System] Initiating deterministic feed synchronization...");
                controller.syncFeeds("NVD");
                break;

            case "query":
                if (args.length > 1) {
                    System.out.println("[User] " + args[1]);
                    System.out.println("[System] Passing context to AI Facade...");
                    
                    // Maps directly to Feature F03
                    String response = controller.handleNaturalQuery(args[1]);
                    
                    System.out.println("\n[Orion AI Agent]\n" + response + "\n");
                } else {
                    System.err.println("Error: Please provide a natural language query string.");
                }
                break;

            default:
                System.err.println("Unknown command: " + command);
                break;
        }
    }

    /**
     * The main execution thread for the Java application.
     * Initializes the database connection and bootstaps the system architecture.
     */
    /*@ requires args != null; @*/
    public static void main(String[] args) {
        try {
            // 1. Initialize SQLite connection
            DatabaseManager dbManager = new DatabaseManager();
            
            // 2. Initialize the deterministic controller and AI facade
            AgentController agentController = new AgentController(dbManager);
            
            // 3. Mount the CLI boundary layer
            OrionCLI cli = new OrionCLI(agentController);
            
            // Simulated execution for easy testing inside VS Code
            // If run without arguments, it defaults to testing the AI query pipeline
            if (args.length == 0) {
                cli.parseAndExecute(new String[]{"query", "What are the latest zero-day threats?"});
            } else {
                cli.parseAndExecute(args);
            }

        } catch (Exception e) {
            System.err.println("Fatal System Boot Error: " + e.getMessage());
        }
    }
}