package ca.yorku.eecs3311.orion.boundary;

import ca.yorku.eecs3311.orion.controller.AgentController;
import ca.yorku.eecs3311.orion.database.DatabaseManager;
import ca.yorku.eecs3311.orion.model.AdvisoryFilter;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import ca.yorku.eecs3311.orion.observer.SecurityObserver;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
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
import javafx.scene.layout.Priority;
import javafx.scene.control.SelectionMode;
import javafx.scene.control.SplitPane;
import javafx.scene.web.WebView;

import java.util.List;

/**
 * Graphical User Interface for Orion Threat Intelligence.
 * Fulfills the boundary layer and Concrete Observer requirements from the Stage 1 UML.
 */
public class OrionGUI extends Application implements SecurityObserver {

    private AgentController controller;
    private TableView<ThreatAdvisory> threatTable;
    private TextField queryInput;
    private WebView displayWebView;
    private javafx.scene.web.WebEngine webEngine;
    private StringBuilder chatHistoryHtml = new StringBuilder();

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
        primaryStage.setResizable(true);

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
        descCol.setPrefWidth(250);

        // --- NEW 7TH COLUMN FOR PUBLISHED DATE ---
        TableColumn<ThreatAdvisory, String> dateCol = new TableColumn<>("Published Date");
        dateCol.setCellValueFactory(new PropertyValueFactory<>("publishedDate"));
        dateCol.setPrefWidth(120);

        // Include dateCol in your setAll list, and remove constrained resize so columns keep fixed intentional sizes
        threatTable.getColumns().setAll(dateCol, idCol, vendorCol, productCol, typeCol, sevCol, descCol);
        threatTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        
        queryInput = new TextField();
        queryInput.setPromptText("Enter your Query Here. Let AI do the heavy lifting!");
        
        displayWebView = new WebView();
        webEngine = displayWebView.getEngine();
        renderWebView(); // Initialize empty canvas

        // Wrap table and WebView in a vertical SplitPane for draggable resizing
        SplitPane splitPane = new SplitPane();
        splitPane.setOrientation(javafx.geometry.Orientation.VERTICAL);
        splitPane.getItems().addAll(threatTable, displayWebView);
        splitPane.setDividerPositions(0.5); // Initial 50/50 split

        // --- ROW 1: Advisory-Specific AI & Sync Features ---
        Button syncBtn = new Button("Sync CISA KEV Feeds (F01)");
        syncBtn.setOnAction(e -> {
            appendSystemLog("Initiating CISA KEV sync...");
            new Thread(() -> controller.syncFeeds("CISA")).start(); 
        });

        Button syncNistBtn = new Button("Sync NIST Feed (F01)");
        syncNistBtn.setOnAction(e -> {
            appendSystemLog("Initiating NIST NVD sync...");
            new Thread(() -> controller.syncFeeds("NIST")).start(); 
        });

        Button summaryBtn = new Button("Summarize Selected (F02)");
        summaryBtn.setOnAction(e -> {
            ThreatAdvisory selected = threatTable.getSelectionModel().getSelectedItem();
            if (selected != null) {
                appendSystemLog("Generating AI summary for " + selected.getId() + "...");
                new Thread(() -> displaySummary(controller.summarizeAdvisory(selected.getId()))).start();
            } else {
                showError("Please select an advisory from the table first.");
            }
        });

        Button mitigateBtn = new Button("Generate Mitigation (F05)");
        mitigateBtn.setOnAction(e -> {
            ThreatAdvisory selected = threatTable.getSelectionModel().getSelectedItem();
            if (selected != null) {
                appendSystemLog("Generating AI mitigation playbook...");
                new Thread(() -> displaySummary(controller.generateMitigationPlaybook(selected.getId(), "Standard Enterprise Environment"))).start();
            } else {
                showError("Please select an advisory from the table first.");
            }
        });

        Button triageBtn = new Button("Auto-Triage (F09)");
        triageBtn.setOnAction(e -> {
            ThreatAdvisory selected = threatTable.getSelectionModel().getSelectedItem();
            if (selected != null) {
                appendSystemLog("Evaluating dynamic triage...");
                new Thread(() -> displaySummary(controller.evaluateAdvisoryTriage(selected.getId(), "Windows Server, AWS Cloud"))).start();
            } else {
                showError("Please select an advisory from the table first.");
            }
        });

        Button gapBtn = new Button("Gap Analysis (F10)");
        gapBtn.setOnAction(e -> {
            ThreatAdvisory selected = threatTable.getSelectionModel().getSelectedItem();
            if (selected != null) {
                appendSystemLog("Evaluating security gaps...");
                new Thread(() -> displaySummary(controller.evaluateSecurityGaps(selected.getId(), java.util.List.of("Firewall", "EDR")))).start();
            } else {
                showError("Please select an advisory from the table first.");
            }
        });

        // --- ROW 2: Utility & System Features ---
        Button correlateBtn = new Button("Correlate Logs (F04)");
        correlateBtn.setOnAction(e -> {
            appendSystemLog("Correlating internal logs...");
            new Thread(() -> {
                java.util.List<String> anomalies = controller.correlateLogs("");
                Platform.runLater(() -> appendSystemLog("Anomalies Found:\n" + String.join("\n", anomalies)));
            }).start();
        });

        Button extractBtn = new Button("Extract IoCs (F06)");
        extractBtn.setOnAction(e -> {
            String text = queryInput.getText();
            if (text.isEmpty()) {
                showError("Please paste text containing IPs or Hashes into the query box first.");
                return;
            }
            appendSystemLog("Extracting IoCs from text...");
            new Thread(() -> {
                java.util.List<String> iocs = controller.extractIocsFromText(text);
                Platform.runLater(() -> appendSystemLog("Extracted IoCs:\n" + String.join("\n", iocs)));
            }).start();
        });

        Button exportBtn = new Button("Export Briefing (F07)");
        exportBtn.setOnAction(e -> {
            java.util.List<ThreatAdvisory> selected = threatTable.getSelectionModel().getSelectedItems();
            if (selected.isEmpty()) {
                showError("Please select at least one advisory from the table to export.");
                return;
            }

            appendSystemLog("Exporting report to report.md...");
            new Thread(() -> {
                boolean success = controller.exportThreatBriefing(new java.util.ArrayList<>(selected), "report.md");
                Platform.runLater(() -> appendSystemLog(success ? "Export complete." : "Export failed."));
            }).start();
        });

        Button filterBtn = new Button("Filter Critical (F08)");
        filterBtn.setOnAction(e -> {
            appendSystemLog("Applying historical filter: CRITICAL...");
            AdvisoryFilter filter = new AdvisoryFilter();
            filter.setSeverityThreshold("CRITICAL");
            List<ThreatAdvisory> filtered = controller.searchAdvisories(filter);
            displayThreats(filtered);
            appendSystemLog("Showing " + filtered.size() + " filtered records.");
        });

        Button resetFilterBtn = new Button("Reset Filter");
        resetFilterBtn.setOnAction(e -> {
            displayThreats(controller.getStoredAdvisories());
            appendSystemLog("Filters reset to all records.");
        });

        // Layout the buttons horizontally
        HBox row1 = new HBox(10, syncBtn, syncNistBtn, summaryBtn, mitigateBtn, triageBtn, gapBtn);
        HBox row2 = new HBox(10, correlateBtn, extractBtn, exportBtn, filterBtn, resetFilterBtn);
        
        VBox root = new VBox(10, row1, row2, splitPane, queryInput);

        VBox.setVgrow(splitPane, Priority.ALWAYS);

        Scene scene = new Scene(root, 1100, 750);

        queryInput.setOnAction(e -> {
            String query = queryInput.getText();
            chatHistoryHtml.append("<div style='color: #333; margin: 6px 0;'><b>You:</b> ").append(escapeHtml(query)).append("</div>");
            queryInput.clear();
            
            new Thread(() -> {
                String response = controller.handleNaturalQuery(query);
                displaySummary(response);
            }).start();
        });

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

    /**
     * Appends a system status log into the HTML console stream.
     */
    public void appendSystemLog(String message) {
        Platform.runLater(() -> {
            chatHistoryHtml.append("<div style='color: #555; font-family: monospace; font-size: 11px; margin-bottom: 4px;'>[System] ")
                           .append(escapeHtml(message)).append("</div>");
            renderWebView();
        });
    }

    /**
     * Renders AI responses with automatic markdown-to-HTML conversion into the WebView.
     */
    /*@ requires summary != null; @*/
    public void displaySummary(String markdownSummary) {
        Platform.runLater(() -> {
            String convertedHtml = convertMarkdownToHtml(markdownSummary);
            chatHistoryHtml.append("<div style='background: #ffffff; border-left: 4px solid #007acc; padding: 12px; margin: 8px 0; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);'>" +
                                   "<b style='color: #007acc;'>Orion AI:</b><br><br>")
                           .append(convertedHtml)
                           .append("</div>");
            renderWebView();
        });
    }

    /**
     * Displays error messages prominently in red inside the console.
     */
    /*@ requires message != null; @*/
    public void showError(String message) {
        Platform.runLater(() -> {
            chatHistoryHtml.append("<div style='color: #d9534f; background: #fdf7f7; border-left: 4px solid #d9534f; padding: 8px; margin: 6px 0; font-family: monospace;'><b>ERROR:</b> ")
                           .append(escapeHtml(message)).append("</div>");
            renderWebView();
        });
    }

    /**
     * Refreshes the WebView content.
     */
    private void renderWebView() {
        String fullHtml = "<html><body style='font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif; font-size: 13px; background-color: #f4f4f4; padding: 10px;'>" +
                chatHistoryHtml.toString() +
                "</body></html>";
        webEngine.loadContent(fullHtml);
    }

    /**
     * Converts markdown headers, bold text, and bullet points into clean HTML tags.
     */
    /**
     * Converts markdown headers, bold, italics, bullets, and blockquotes into clean HTML tags.
     */
    private String convertMarkdownToHtml(String markdown) {
        if (markdown == null) return "";
        
        String html = escapeHtml(markdown);
        
        // Convert headers
        html = html.replaceAll("(?m)^###\\s+(.*)$", "<h4 style='color: #333; margin: 8px 0 4px 0;'>$1</h4>");
        html = html.replaceAll("(?m)^##\\s+(.*)$", "<h3 style='color: #222; margin: 10px 0 4px 0;'>$1</h3>");
        html = html.replaceAll("(?m)^#\\s+(.*)$", "<h2 style='color: #111; margin: 12px 0 6px 0;'>$1</h2>");
        
        // Convert bold (**text** -> <b>) - MUST be done before italics
        html = html.replaceAll("\\*\\*(.*?)\\*\\*", "<b>$1</b>");
        
        // Convert italics (*text* -> <i>)
        html = html.replaceAll("\\*(.*?)\\*", "<i>$1</i>");
        
        // Convert list bullets starting with '-' or '*' -> <li>
        html = html.replaceAll("(?m)^-\\s+(.*)$", "<li style='margin-left: 15px;'>$1</li>");
        html = html.replaceAll("(?m)^\\*\\s+(.*)$", "<li style='margin-left: 15px;'>$1</li>");
        
        // Convert blockquotes (> text -> <blockquote>)
        html = html.replaceAll("(?m)^>\\s+(.*)$", "<blockquote style='border-left: 3px solid #007acc; margin: 5px 0; padding-left: 10px; color: #555;'>$1</blockquote>");
        
        // Convert newlines to breaks
        html = html.replace("\n", "<br>");
        return html;
    }

    private String escapeHtml(String str) {
        return str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
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
                appendSystemLog("Sync completed successfully. " + data + " records processed.");
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