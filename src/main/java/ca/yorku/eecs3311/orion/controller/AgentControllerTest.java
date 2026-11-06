package ca.yorku.eecs3311.orion.controller;

import ca.yorku.eecs3311.orion.command.BlockIpCommand;
import ca.yorku.eecs3311.orion.database.DatabaseManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the AgentController and core command execution safety nets.
 */
public class AgentControllerTest {

    private AgentController controller;
    private DatabaseManager dbManager;

    @BeforeEach
    public void setUp() throws Exception{
        // Initialize an in-memory or local test database connection
        dbManager = new DatabaseManager();
        controller = new AgentController(dbManager);
    }

    @Test
    public void testCommandExecutionAndUndo() {
        BlockIpCommand cmd = new BlockIpCommand("192.168.1.100");
        
        // Test execution
        boolean executed = controller.executeCommand(cmd);
        assertTrue(executed, "Command execution should succeed.");

        // Test rollback / undo
        boolean undone = controller.undoLastCommand();
        assertTrue(undone, "Command undo operation should succeed.");
    }

    @Test
    public void testNaturalQueryRouting() {
        // Test that natural language queries pass through the facade without crashing
        String response = controller.handleNaturalQuery("Test security query");
        assertNotNull(response, "Agent response should not be null.");
    }

    @Test
    public void testIocExtractionIntegration() {
        String sampleText = "Attackers compromised host using IP 192.168.1.50 and hash 5d41402abc4b2a76b9719d911017c592.";
        var iocs = controller.extractIocsFromText(sampleText);
        
        assertNotNull(iocs, "Extracted IoCs list should not be null.");
        assertTrue(iocs.size() >= 2, "Should successfully extract both the IP address and hash.");
    }
}