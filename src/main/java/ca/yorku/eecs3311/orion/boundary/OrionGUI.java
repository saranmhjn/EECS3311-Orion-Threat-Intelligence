package ca.yorku.eecs3311.orion.boundary;

import ca.yorku.eecs3311.orion.controller.AgentController;
import ca.yorku.eecs3311.orion.database.DatabaseManager;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import ca.yorku.eecs3311.orion.observer.SecurityObserver;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.TableView;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.util.List;

/**
 * Graphical User Interface for Orion Threat Intelligence.
 * Fulfills the boundary layer and Concrete Observer requirements from the Stage 1 UML.
 */
public class OrionGUI extends Application implements SecurityObserver {

    private AgentController controller;
    private TableView<ThreatAdvisory> threatTable;
    private TextField queryInput;
    private TextArea displayArea;

    /*@ public invariant controller != null; @*/

    /**
     * Initializes the backend controller and database before the UI renders.
     */
    @Override
    public void init() throws Exception {
        DatabaseManager dbManager = new DatabaseManager();
        this.controller = new AgentController(dbManager);
        
        // Register this GUI as an observer to listen for backend events (Observer Pattern)
        this.controller.addObserver(this);
    }

    /**
     * Constructs the visual JavaFX elements.
     */
    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Orion Threat Intelligence");

        threatTable = new TableView<>();
        queryInput = new TextField();
        queryInput.setPromptText("Ask the AI about the threat landscape (e.g., 'What are zero-day threats?')...");
        
        displayArea = new TextArea();
        displayArea.setEditable(false);

        VBox root = new VBox(10, threatTable, displayArea, queryInput);
        Scene scene = new Scene(root, 800, 600);

        // Event handler for Natural Language Querying (Feature F03)
        queryInput.setOnAction(e -> {
            String query = queryInput.getText();
            displayArea.appendText("You: " + query + "\n");
            queryInput.clear();
            
            // Pass the query to the AgentController, which routes to the AI Facade
            String response = controller.handleNaturalQuery(query);
            displaySummary(response);
        });

        primaryStage.setScene(scene);
        primaryStage.show();
    }

    /*@ requires threats != null; @*/
    public void displayThreats(List<ThreatAdvisory> threats) {
        // Implementation stub for populating the TableView
    }

    /*@ requires summary != null; @*/
    public void displaySummary(String summary) {
        // Platform.runLater ensures UI updates happen safely on the JavaFX Application Thread
        Platform.runLater(() -> displayArea.appendText("Orion AI: " + summary + "\n\n"));
    }

    /*@ requires message != null; @*/
    public void showError(String message) {
        Platform.runLater(() -> displayArea.appendText("ERROR: " + message + "\n"));
    }

    public void updateProgress(double progress) {
        // Implementation stub for a progress bar
    }

    /**
     * Fulfills the SecurityObserver contract. 
     * Handles background events triggered by the AgentController.
     */
    @Override
    public void onSecurityEvent(String eventType, Object data) {
        Platform.runLater(() -> {
            if ("SYNC_COMPLETE".equals(eventType)) {
                displayArea.appendText("[System] Sync completed successfully. " + data + " records processed.\n");
            } else if ("SYNC_ERROR".equals(eventType)) {
                showError(data.toString());
            }
        });
    }
    
    public static void main(String[] args) {
        launch(args);
    }
}