package ca.yorku.eecs3311.orion.boundary;

import ca.yorku.eecs3311.orion.controller.AgentController;
import ca.yorku.eecs3311.orion.database.DatabaseManager;
import ca.yorku.eecs3311.orion.model.AdvisoryFilter;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import ca.yorku.eecs3311.orion.observer.SecurityObserver;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.control.TableView;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.TableColumn;
import javafx.scene.control.Button;
import javafx.scene.layout.HBox;
import javafx.scene.control.SelectionMode;

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
        threatTable.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
        
       TableColumn<ThreatAdvisory, String> idCol = new TableColumn<>("CVE ID");
        idCol.setCellValueFactory(new PropertyValueFactory<>("id"));
        idCol.setPrefWidth(120);

        TableColumn<ThreatAdvisory, String> vendorCol = new TableColumn<>("Vendor");
        vendorCol.setCellValueFactory(new PropertyValueFactory<>("vendor"));
        vendorCol.setPrefWidth(110);

        TableColumn<ThreatAdvisory, String> productCol = new TableColumn<>("Product");
        productCol.setCellValueFactory(new PropertyValueFactory<>("product"));
        productCol.setPrefWidth(130);

        TableColumn<ThreatAdvisory, String> typeCol = new TableColumn<>("Threat Type");
        typeCol.setCellValueFactory(new PropertyValueFactory<>("threatType"));
        typeCol.setPrefWidth(130);

        TableColumn<ThreatAdvisory, String> sevCol = new TableColumn<>("Severity");
        sevCol.setCellValueFactory(new PropertyValueFactory<>("severity"));
        sevCol.setPrefWidth(90);

        TableColumn<ThreatAdvisory, String> descCol = new TableColumn<>("Description");
        descCol.setCellValueFactory(new PropertyValueFactory<>("description"));
        descCol.setPrefWidth(300);

        threatTable.getColumns().setAll(idCol, vendorCol, productCol, typeCol, sevCol, descCol);
        
        queryInput = new TextField();
        queryInput.setPromptText("Ask the AI about the threat landscape (e.g., 'What are zero-day threats?')...");
        
        displayArea = new TextArea();
        displayArea.setEditable(false);

// --- ROW 1: Advisory-Specific AI Features ---
        Button syncBtn = new Button("Sync CISA KEV Feeds (F01)");
        syncBtn.setOnAction(e -> {
            displayArea.appendText("[System] Initiating CISA KEV sync...\n");
            new Thread(() -> controller.syncFeeds("CISA")).start(); 
        });

        Button summaryBtn = new Button("Summarize Selected (F02)");
        summaryBtn.setOnAction(e -> {
            ThreatAdvisory selected = threatTable.getSelectionModel().getSelectedItem();
            if (selected != null) {
                displayArea.appendText("[System] Generating AI summary for " + selected.getId() + "...\n");
                new Thread(() -> displaySummary(controller.summarizeAdvisory(selected.getId()))).start();
            } else {
                showError("Please select an advisory from the table first.");
            }
        });

        Button mitigateBtn = new Button("Generate Mitigation (F05)");
        mitigateBtn.setOnAction(e -> {
            ThreatAdvisory selected = threatTable.getSelectionModel().getSelectedItem();
            if (selected != null) {
                displayArea.appendText("[System] Generating AI mitigation playbook...\n");
                new Thread(() -> displaySummary(controller.generateMitigationPlaybook(selected.getId(), "Standard Enterprise Environment"))).start();
            } else {
                showError("Please select an advisory from the table first.");
            }
        });

        Button triageBtn = new Button("Auto-Triage (F09)");
        triageBtn.setOnAction(e -> {
            ThreatAdvisory selected = threatTable.getSelectionModel().getSelectedItem();
            if (selected != null) {
                displayArea.appendText("[System] Evaluating dynamic triage...\n");
                new Thread(() -> displaySummary(controller.evaluateAdvisoryTriage(selected.getId(), "Windows Server, AWS Cloud"))).start();
            } else {
                showError("Please select an advisory from the table first.");
            }
        });

        Button gapBtn = new Button("Gap Analysis (F10)");
        gapBtn.setOnAction(e -> {
            ThreatAdvisory selected = threatTable.getSelectionModel().getSelectedItem();
            if (selected != null) {
                displayArea.appendText("[System] Evaluating security gaps...\n");
                new Thread(() -> displaySummary(controller.evaluateSecurityGaps(selected.getId(), java.util.List.of("Firewall", "EDR")))).start();
            } else {
                showError("Please select an advisory from the table first.");
            }
        });

        // --- ROW 2: Utility & System Features ---
        Button correlateBtn = new Button("Correlate Logs (F04)");
        correlateBtn.setOnAction(e -> {
            displayArea.appendText("[System] Correlating internal logs...\n");
            new Thread(() -> {
                java.util.List<String> anomalies = controller.correlateLogs(""); // Uses your fallback simulation
                Platform.runLater(() -> displayArea.appendText("Anomalies Found:\n" + String.join("\n", anomalies) + "\n\n"));
            }).start();
        });

        Button extractBtn = new Button("Extract IoCs (F06)");
        extractBtn.setOnAction(e -> {
            String text = queryInput.getText();
            if (text.isEmpty()) {
                showError("Please paste text containing IPs or Hashes into the query box first.");
                return;
            }
            displayArea.appendText("[System] Extracting IoCs from text...\n");
            new Thread(() -> {
                java.util.List<String> iocs = controller.extractIocsFromText(text);
                Platform.runLater(() -> displayArea.appendText("Extracted IoCs:\n" + String.join("\n", iocs) + "\n\n"));
            }).start();
        });

        Button exportBtn = new Button("Export Briefing (F07)");
        exportBtn.setOnAction(e -> {
            // Grab all selected rows
            java.util.List<ThreatAdvisory> selected = threatTable.getSelectionModel().getSelectedItems();

            if (selected.isEmpty()) {
                showError("Please select at least one advisory from the table to export.");
                return;
            }

            displayArea.appendText("[System] Exporting report to report.md...\n");
            new Thread(() -> {
                // Export only the selected items
                boolean success = controller.exportThreatBriefing(new java.util.ArrayList<>(selected), "report.md");
                Platform.runLater(() -> displayArea.appendText(success ? "[System] Export complete.\n" : "[System] Export failed.\n"));
            }).start();
            
     });
     Button filterBtn = new Button("Filter Critical (F08)");
        filterBtn.setOnAction(e -> {
            displayArea.appendText("[System] Applying historical filter: CRITICAL (KEV)...\n");
            AdvisoryFilter filter = new AdvisoryFilter();
            filter.setSeverityThreshold("CRITICAL (KEV)");
            List<ThreatAdvisory> filtered = controller.searchAdvisories(filter);
            displayThreats(filtered);
            displayArea.appendText("[System] Showing " + filtered.size() + " filtered records.\n");
        });

        Button resetFilterBtn = new Button("Reset Filter");
        resetFilterBtn.setOnAction(e -> {
            displayThreats(controller.getStoredAdvisories());
            displayArea.appendText("[System] Filters reset to all records.\n");
        });
        

        // Layout the buttons horizontally
        HBox row1 = new HBox(10, syncBtn, summaryBtn, mitigateBtn, triageBtn, gapBtn);
        HBox row2 = new HBox(10, correlateBtn, extractBtn, exportBtn, filterBtn, resetFilterBtn);
        
        // Replace your old VBox root instantiation with this one:
        VBox root = new VBox(10, row1, row2, threatTable, displayArea, queryInput);

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

           
       // Fetch existing advisories from database on startup via the Controller
        List<ThreatAdvisory> initialThreats = controller.getStoredAdvisories();
        displayThreats(initialThreats);

        primaryStage.setScene(scene);
        primaryStage.show();
    }

    /**
     * Fills the TableView with fetched threat advisories safely on the JavaFX thread.
     */
    /*@ requires threats != null; @*/
    public void displayThreats(List<ThreatAdvisory> threats) {
        Platform.runLater(() -> {
            ObservableList<ThreatAdvisory> data = FXCollections.observableArrayList(threats);
            threatTable.setItems(data);
        });
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
                
                // Refresh table with all stored advisories from database
                List<ThreatAdvisory> updatedThreats = controller.getStoredAdvisories();
                displayThreats(updatedThreats);
                
            } else if ("SYNC_ERROR".equals(eventType)) {
                showError(data.toString());
            }
        });
    }
    
    public static void main(String[] args) {
        launch(args);
    }
}