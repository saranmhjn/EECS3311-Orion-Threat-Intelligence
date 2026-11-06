package ca.yorku.eecs3311.orion.boundary;

import ca.yorku.eecs3311.orion.controller.AgentController;
import ca.yorku.eecs3311.orion.database.DatabaseManager;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;
import ca.yorku.eecs3311.orion.observer.SecurityObserver;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.paint.LinearGradient;
import javafx.scene.paint.CycleMethod;
import javafx.scene.paint.Stop;
import javafx.scene.shape.Circle;
import javafx.scene.web.WebView;
import javafx.stage.Stage;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

/**
 * Modern, glossy Cyber Threat Intelligence visual workspace.
 * Features a dynamic custom vector logo, dual-row grid alignment, 
 * multi-select dropdown filtering, and an optimized 70/30 split layout.
 */
public class OrionGUI extends Application implements SecurityObserver {

    private AgentController controller;
    private TableView<ThreatAdvisory> threatTable;
    private TextField queryInput;
    private WebView displayWebView;
    private javafx.scene.web.WebEngine webEngine;
    private WebView carouselWebView; 
    private StringBuilder chatHistoryHtml = new StringBuilder();

    @Override
    public void init() throws Exception {
        DatabaseManager dbManager = new DatabaseManager();
        this.controller = new AgentController(dbManager);
        this.controller.addObserver(this);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        primaryStage.setTitle("Orion Threat Intelligence | AI Assistant");
        primaryStage.setResizable(true);

        // --- 1. CODE-BASED CYBER VECTOR LOGO ---
        HBox brandingContainer = new HBox(15);
        brandingContainer.setAlignment(Pos.CENTER);
        brandingContainer.setPadding(new Insets(10, 0, 15, 0));

        StackPane vectorLogo = new StackPane();
        vectorLogo.setPrefSize(50, 50);

        Circle outerOrbit = new Circle(24);
        outerOrbit.setFill(Color.TRANSPARENT);
        outerOrbit.setStroke(new LinearGradient(0, 0, 1, 1, true, CycleMethod.NO_CYCLE,
                new Stop(0, Color.web("#00f2fe")),
                new Stop(1, Color.web("#e94057"))));
        outerOrbit.setStrokeWidth(2.5);
        outerOrbit.setStyle("-fx-effect: dropshadow(gaussian, rgba(0, 242, 254, 0.45), 6, 0, 0, 0);");

        Circle innerShield = new Circle(18);
        innerShield.setFill(Color.web("#161233"));
        innerShield.setStroke(Color.web("#8a2387"));
        innerShield.setStrokeWidth(1.5);

        Label crestText = new Label("O");
        crestText.setStyle("-fx-font-size: 20px; -fx-font-weight: 900; -fx-text-fill: white; -fx-effect: dropshadow(gaussian, #e94057, 5, 0, 0, 0);");

        vectorLogo.getChildren().addAll(outerOrbit, innerShield, crestText);
        brandingContainer.getChildren().add(vectorLogo);

        VBox titleArea = new VBox(2);
        titleArea.setAlignment(Pos.CENTER_LEFT);
        Label title = new Label("O R I O N   ·   T H R E A T   I N T E L L I G E N C E");
        title.setStyle("-fx-font-size: 24px; -fx-font-weight: 900; -fx-text-fill: white; -fx-effect: dropshadow(gaussian, rgba(0,0,0,0.6), 8, 0, 0, 2);");
        Label subtitle = new Label("What can I help you investigate today?");
        subtitle.setStyle("-fx-font-size: 18px; -fx-text-fill: #a0a0b5; -fx-font-weight: bold;");
        titleArea.getChildren().addAll(title, subtitle);
        brandingContainer.getChildren().add(titleArea);

        // --- 2. THE THREAT TABLE ---
        threatTable = new TableView<>();
        threatTable.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);

        javafx.util.Callback<TableColumn<ThreatAdvisory, String>, TableCell<ThreatAdvisory, String>> centerCellFactory = col -> {
            TableCell<ThreatAdvisory, String> cell = new TableCell<>() {
                @Override
                protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setText(null);
                        setGraphic(null);
                    } else {
                        setText(item);
                        setWrapText(true);
                    }
                }
            };
            cell.setAlignment(Pos.CENTER);
            return cell;
        };
        
        TableColumn<ThreatAdvisory, String> dateCol = new TableColumn<>("Published Date");
        dateCol.setCellValueFactory(new PropertyValueFactory<>("publishedDate"));
        dateCol.setPrefWidth(110);

        TableColumn<ThreatAdvisory, String> idCol = new TableColumn<>("CVE ID");
        idCol.setCellValueFactory(new PropertyValueFactory<>("id"));
        idCol.setPrefWidth(120);

        TableColumn<ThreatAdvisory, String> vendorCol = new TableColumn<>("Vendor");
        vendorCol.setCellValueFactory(new PropertyValueFactory<>("vendor"));
        vendorCol.setPrefWidth(100);

        TableColumn<ThreatAdvisory, String> productCol = new TableColumn<>("Product");
        productCol.setCellValueFactory(new PropertyValueFactory<>("product"));
        productCol.setPrefWidth(120);

        TableColumn<ThreatAdvisory, String> typeCol = new TableColumn<>("Threat Type");
        typeCol.setCellValueFactory(new PropertyValueFactory<>("threatType"));
        typeCol.setPrefWidth(120);

        TableColumn<ThreatAdvisory, String> sevCol = new TableColumn<>("Severity");
        sevCol.setCellValueFactory(new PropertyValueFactory<>("severity"));
        sevCol.setPrefWidth(80);

        TableColumn<ThreatAdvisory, String> descCol = new TableColumn<>("Description");
        descCol.setCellValueFactory(new PropertyValueFactory<>("description"));
        descCol.setPrefWidth(250);

        threatTable.getColumns().setAll(dateCol, idCol, vendorCol, productCol, typeCol, sevCol, descCol);
        threatTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);

        // --- 3. THE AI DISPLAY & GLOSSY PROMPT FIELD ---
        displayWebView = new WebView();
        webEngine = displayWebView.getEngine();
        
        // Auto-scroll logic
        webEngine.getLoadWorker().stateProperty().addListener((obs, oldState, newState) -> {
            if (newState == javafx.concurrent.Worker.State.SUCCEEDED) {
                webEngine.executeScript("window.scrollTo(0, document.body.scrollHeight);");
            }
        });
        renderWebView(); 

        HBox searchBar = new HBox(12);
        searchBar.setAlignment(Pos.CENTER_LEFT);
        searchBar.getStyleClass().add("search-bar");

        Label searchIcon = new Label("🔍");
        searchIcon.setStyle("-fx-text-fill: #00f2fe; -fx-font-size: 18px; -fx-padding: 0 0 0 15; -fx-effect: dropshadow(gaussian, rgba(0,242,254,0.3), 5, 0, 0, 0);");

        queryInput = new TextField();
        queryInput.setPromptText("Analyze threats, generate playbooks, or correlate logs...");
        queryInput.getStyleClass().add("search-input");
        queryInput.setPrefHeight(45);
        HBox.setHgrow(queryInput, Priority.ALWAYS);

        Button sendBtn = new Button("➔");
        sendBtn.getStyleClass().add("send-btn");
        sendBtn.setOnAction(e -> handleQuerySubmission());
        queryInput.setOnAction(e -> handleQuerySubmission()); 

        searchBar.getChildren().addAll(searchIcon, queryInput, sendBtn);
        searchBar.setPadding(new Insets(6, 12, 6, 0));

        VBox rightWorkspace = new VBox(15, displayWebView, searchBar);
        VBox.setVgrow(displayWebView, Priority.ALWAYS);
        rightWorkspace.setPadding(new Insets(10));

        SplitPane splitPane = new SplitPane();
        splitPane.setOrientation(javafx.geometry.Orientation.HORIZONTAL); 
        splitPane.getItems().addAll(threatTable, rightWorkspace);
        // UPDATED: 70/30 Split layout for wider table visibility
        splitPane.setDividerPositions(0.70); 

        // --- 4. ALIGNED ACTION BUTTONS (GRID LAYOUT) ---
        GridPane actionGrid = new GridPane();
        actionGrid.setHgap(12);
        actionGrid.setVgap(12);
        actionGrid.setPadding(new Insets(0, 0, 15, 0));

        ColumnConstraints col1 = new ColumnConstraints(); col1.setPercentWidth(14.28);
        ColumnConstraints col2 = new ColumnConstraints(); col2.setPercentWidth(14.28);
        ColumnConstraints col3 = new ColumnConstraints(); col3.setPercentWidth(14.28);
        ColumnConstraints col4 = new ColumnConstraints(); col4.setPercentWidth(14.28);
        ColumnConstraints col5 = new ColumnConstraints(); col5.setPercentWidth(14.28);
        ColumnConstraints col6 = new ColumnConstraints(); col6.setPercentWidth(14.28);
        ColumnConstraints col7 = new ColumnConstraints(); col7.setPercentWidth(14.28);
        actionGrid.getColumnConstraints().addAll(col1, col2, col3, col4, col5, col6, col7);

        Button summaryBtn = new Button("✨ Summarize Selected");
        summaryBtn.setMaxWidth(Double.MAX_VALUE);
        summaryBtn.setTooltip(new Tooltip("Generate an executive AI summary of the selected CVE"));
        summaryBtn.setOnAction(e -> executeAdvisoryAction("Generating AI summary", id -> controller.summarizeAdvisory(id)));

        Button mitigateBtn = new Button("🛡️ Generate Mitigation");
        mitigateBtn.setMaxWidth(Double.MAX_VALUE);
        mitigateBtn.setTooltip(new Tooltip("Draft an enterprise remediation playbook for the selected threat"));
        mitigateBtn.setOnAction(e -> executeAdvisoryAction("Generating mitigation playbook", id -> controller.generateMitigationPlaybook(id, "Standard Enterprise Environment")));

        Button triageBtn = new Button("⚡ Auto-Triage");
        triageBtn.setMaxWidth(Double.MAX_VALUE);
        triageBtn.setTooltip(new Tooltip("Evaluate severity against your specific cloud/server environment"));
        triageBtn.setOnAction(e -> executeAdvisoryAction("Evaluating dynamic triage", id -> controller.evaluateAdvisoryTriage(id, "Windows Server, AWS Cloud")));

        Button gapBtn = new Button("🔍 Gap Analysis");
        gapBtn.setMaxWidth(Double.MAX_VALUE);
        gapBtn.setTooltip(new Tooltip("Analyze potential bypasses in your Firewall and EDR solutions"));
        gapBtn.setOnAction(e -> executeAdvisoryAction("Evaluating security gaps", id -> controller.evaluateSecurityGaps(id, List.of("Firewall", "EDR"))));

        Button correlateBtn = new Button("📊 Correlate Logs");
        correlateBtn.setMaxWidth(Double.MAX_VALUE);
        correlateBtn.setTooltip(new Tooltip("Scan local audit logs for known threat indicators"));
        correlateBtn.setOnAction(e -> {
            appendSystemLog("Correlating internal logs...");
            new Thread(() -> {
                List<String> anomalies = controller.correlateLogs("");
                Platform.runLater(() -> appendSystemLog("Anomalies Found:\n" + String.join("\n", anomalies)));
            }).start();
        });

        Button extractBtn = new Button("📤 Extract IoCs");
        extractBtn.setMaxWidth(Double.MAX_VALUE);
        extractBtn.setTooltip(new Tooltip("Extract and defang IPs, Hashes, and Domains from the query input box"));
        extractBtn.setOnAction(e -> {
            String text = queryInput.getText();
            if (text.isEmpty()) { showError("Please paste text containing IPs/Hashes in the query box first."); return; }
            appendSystemLog("Extracting IoCs from text...");
            new Thread(() -> {
                List<String> iocs = controller.extractIocsFromText(text);
                Platform.runLater(() -> appendSystemLog("Extracted IoCs:\n" + String.join("\n", iocs)));
            }).start();
        });

        Button exportBtn = new Button("📄 Export Briefing");
        exportBtn.setMaxWidth(Double.MAX_VALUE);
        exportBtn.setTooltip(new Tooltip("Export selected advisories to a Markdown briefing report"));
        exportBtn.setOnAction(e -> {
            List<ThreatAdvisory> selected = threatTable.getSelectionModel().getSelectedItems();
            if (selected.isEmpty()) { showError("Select at least one advisory to export."); return; }
            appendSystemLog("Exporting report to report.md...");
            new Thread(() -> {
                boolean success = controller.exportThreatBriefing(new java.util.ArrayList<>(selected), "report.md");
                Platform.runLater(() -> appendSystemLog(success ? "Export complete." : "Export failed."));
            }).start();
        });

        actionGrid.add(summaryBtn, 0, 0);
        actionGrid.add(mitigateBtn, 1, 0);
        actionGrid.add(triageBtn, 2, 0);
        actionGrid.add(gapBtn, 3, 0);
        actionGrid.add(correlateBtn, 4, 0);
        actionGrid.add(extractBtn, 5, 0);
        actionGrid.add(exportBtn, 6, 0);

        Button syncBtn = new Button("🔄 Sync CISA KEV");
        syncBtn.setMaxWidth(Double.MAX_VALUE);
        syncBtn.setTooltip(new Tooltip("Ingest latest Known Exploited Vulnerabilities from CISA"));
        syncBtn.setOnAction(e -> { appendSystemLog("Initiating CISA KEV sync..."); new Thread(() -> controller.syncFeeds("CISA")).start(); });

        Button syncNistBtn = new Button("🔄 Sync NIST Feed");
        syncNistBtn.setMaxWidth(Double.MAX_VALUE);
        syncNistBtn.setTooltip(new Tooltip("Ingest latest CVEs from the NIST National Vulnerability Database"));
        syncNistBtn.setOnAction(e -> { appendSystemLog("Initiating NIST NVD sync..."); new Thread(() -> controller.syncFeeds("NIST")).start(); });

        // --- NEW: MULTI-SELECT DROPDOWN FILTER (GUI-Side Fast Filter) ---
        MenuButton filterMenu = new MenuButton("⚠️ Filter Severity");
        filterMenu.setMaxWidth(Double.MAX_VALUE);
        filterMenu.getStyleClass().add("menu-button"); // Bind to new CSS below
        filterMenu.setTooltip(new Tooltip("Select one or more severities to filter the table instantly"));

        CheckMenuItem critItem = new CheckMenuItem("CRITICAL");
        CheckMenuItem highItem = new CheckMenuItem("HIGH");
        CheckMenuItem medItem = new CheckMenuItem("MEDIUM");
        CheckMenuItem lowItem = new CheckMenuItem("LOW");

        javafx.event.EventHandler<javafx.event.ActionEvent> filterAction = e -> {
            List<String> selected = new ArrayList<>();
            if (critItem.isSelected()) selected.add("CRITICAL");
            if (highItem.isSelected()) selected.add("HIGH");
            if (medItem.isSelected()) selected.add("MEDIUM");
            if (lowItem.isSelected()) selected.add("LOW");

            if (selected.isEmpty()) {
                displayThreats(controller.getStoredAdvisories());
            } else {
                List<ThreatAdvisory> all = controller.getStoredAdvisories();
                List<ThreatAdvisory> filtered = new ArrayList<>();
                for (ThreatAdvisory adv : all) {
                    if (adv.getSeverity() != null && selected.contains(adv.getSeverity().toUpperCase())) {
                        filtered.add(adv);
                    }
                }
                displayThreats(filtered);
            }
        };

        critItem.setOnAction(filterAction);
        highItem.setOnAction(filterAction);
        medItem.setOnAction(filterAction);
        lowItem.setOnAction(filterAction);
        filterMenu.getItems().addAll(critItem, highItem, medItem, lowItem);

        Button resetFilterBtn = new Button("✖ Reset Filter");
        resetFilterBtn.setMaxWidth(Double.MAX_VALUE);
        resetFilterBtn.setTooltip(new Tooltip("Clear all filters and display the full database"));
        resetFilterBtn.setOnAction(e -> {
            critItem.setSelected(false);
            highItem.setSelected(false);
            medItem.setSelected(false);
            lowItem.setSelected(false);
            displayThreats(controller.getStoredAdvisories());
        });

        actionGrid.add(syncBtn, 0, 1);
        actionGrid.add(syncNistBtn, 1, 1);
        actionGrid.add(filterMenu, 5, 1);
        actionGrid.add(resetFilterBtn, 6, 1);

        // --- 5. ENDLESS THEMED CAROUSEL WEBVIEW ---
        carouselWebView = new WebView();
        carouselWebView.setMinHeight(34);
        carouselWebView.setPrefHeight(34);
        carouselWebView.setMaxHeight(34);
        carouselWebView.getStyleClass().add("carousel-container");

        carouselWebView.getEngine().locationProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal != null && !newVal.equals("about:blank") && !newVal.startsWith("data:")) {
                Platform.runLater(() -> {
                    loadCarouselData(); 
                    getHostServices().showDocument(newVal); 
                });
            }
        });
        loadCarouselData();

        Label copyright = new Label("© 2026 Orion Threat Intelligence. All rights reserved.");
        copyright.setStyle("-fx-text-fill: #666677; -fx-font-size: 11px;");
        HBox footer = new HBox(copyright);
        footer.setAlignment(Pos.CENTER);
        footer.setPadding(new Insets(5, 0, 0, 0));

        // --- 6. ROOT SETUP & STYLES ---
        VBox root = new VBox(10, brandingContainer, actionGrid, splitPane, carouselWebView, footer);
        root.setPadding(new Insets(20, 20, 10, 20));
        VBox.setVgrow(splitPane, Priority.ALWAYS);
        Scene scene = new Scene(root, 1400, 850);

        String css = ".root { -fx-background-color: linear-gradient(to bottom right, #0a081a, #161233, #1c142c); -fx-font-family: 'Segoe UI', sans-serif; }"
            
            /* UPDATED: Buttons now have 14.5px font size and tighter 8 16 padding to fix bulky look */
            + ".button { -fx-background-color: linear-gradient(to right, rgba(138, 35, 135, 0.4), rgba(233, 64, 87, 0.4)); -fx-text-fill: white; -fx-font-weight: bold; -fx-font-size: 14.5px; -fx-border-color: rgba(255,255,255,0.25); -fx-border-radius: 12; -fx-background-radius: 12; -fx-padding: 8 16; -fx-cursor: hand; -fx-effect: dropshadow(gaussian, rgba(0,0,0,0.3), 8, 0, 0, 3); }"
            + ".button:hover { -fx-background-color: linear-gradient(to right, rgba(138, 35, 135, 0.65), rgba(233, 64, 87, 0.65)); -fx-border-color: rgba(255,255,255,0.45); }"
            
            /* NEW: Match MenuButton to standard button styling */
            + ".menu-button { -fx-background-color: linear-gradient(to right, rgba(138, 35, 135, 0.4), rgba(233, 64, 87, 0.4)); -fx-border-color: rgba(255,255,255,0.25); -fx-border-radius: 12; -fx-background-radius: 12; -fx-padding: 3 12; -fx-cursor: hand; -fx-effect: dropshadow(gaussian, rgba(0,0,0,0.3), 8, 0, 0, 3); }"
            + ".menu-button:hover { -fx-background-color: linear-gradient(to right, rgba(138, 35, 135, 0.65), rgba(233, 64, 87, 0.65)); -fx-border-color: rgba(255,255,255,0.45); }"
            + ".menu-button > .label { -fx-text-fill: white; -fx-font-weight: bold; -fx-font-size: 14.5px; }"
            + ".context-menu { -fx-background-color: #161233; -fx-border-color: #e94057; -fx-border-width: 1px; -fx-border-radius: 4; -fx-background-radius: 4; }"
            + ".menu-item .label { -fx-text-fill: white; -fx-font-size: 13.5px; }"
            + ".menu-item:focused { -fx-background-color: rgba(233, 64, 87, 0.5); }"

            + ".search-bar { -fx-background-color: linear-gradient(to bottom right, rgba(255, 255, 255, 0.08), rgba(255, 255, 255, 0.03)); -fx-border-color: rgba(0, 242, 254, 0.35); -fx-border-radius: 35; -fx-background-radius: 35; -fx-effect: dropshadow(gaussian, rgba(0, 242, 254, 0.25), 12, 0.5, 0, 0); }"
            + ".search-input { -fx-background-color: transparent; -fx-text-fill: white; -fx-font-size: 15px; -fx-prompt-text-fill: #85859e; }"
            + ".search-input:focused { -fx-background-color: transparent; }"
            + ".send-btn { -fx-background-color: linear-gradient(to bottom right, #00f2fe, #4facfe); -fx-text-fill: #0a081a; -fx-border-radius: 50em; -fx-background-radius: 50em; -fx-min-width: 42px; -fx-min-height: 42px; -fx-font-size: 18px; -fx-font-weight: 900; -fx-padding: 0; -fx-effect: dropshadow(gaussian, rgba(0,242,254,0.4), 8, 0, 0, 2); -fx-cursor: hand; }"
            + ".send-btn:hover { -fx-background-color: linear-gradient(to bottom right, #24f4ff, #62b8ff); -fx-effect: dropshadow(gaussian, rgba(0,242,254,0.6), 12, 0, 0, 2); }"
            
            + ".table-view { -fx-background-color: transparent; -fx-border-color: transparent; }"
            + ".table-view .column-header-background { -fx-background-color: rgba(0,0,0,0.5); }"
            + ".table-view .column-header { -fx-background-color: transparent; }"
            + ".table-view .column-header .label { -fx-text-fill: #00f2fe; -fx-font-size: 14px; -fx-font-weight: 900; -fx-effect: dropshadow(gaussian, rgba(0,242,254,0.4), 4, 0, 0, 0); }" 
            + ".table-view .table-cell { -fx-text-fill: #ffffff; -fx-font-size: 13px; -fx-font-weight: 500; -fx-border-color: transparent transparent rgba(255,255,255,0.05) transparent; }" 
            + ".table-row-cell { -fx-background-color: rgba(255,255,255,0.03); }" 
            + ".table-row-cell:odd { -fx-background-color: rgba(255,255,255,0.07); }" 
            + ".table-row-cell:selected { -fx-background-color: linear-gradient(to right, rgba(233, 64, 87, 0.45), rgba(0, 242, 254, 0.2)); -fx-font-weight: 900; }" 
            
            + ".split-pane { -fx-background-color: transparent; }"
            + ".split-pane *.split-pane-divider { -fx-background-color: rgba(255,255,255,0.1); -fx-padding: 0 2 0 2; }"
            + ".tooltip { -fx-background-color: rgba(10, 8, 26, 0.95); -fx-text-fill: white; -fx-font-size: 12px; -fx-border-color: rgba(0, 242, 254, 0.3); -fx-border-radius: 6; -fx-background-radius: 6; -fx-padding: 8 12; }"
            + ".carousel-container { -fx-background-color: transparent; -fx-border-color: transparent; }"
            
            + ".table-view .scroll-bar:vertical, .table-view .scroll-bar:horizontal { -fx-background-color: transparent; }"
            + ".table-view .scroll-bar:vertical .track, .table-view .scroll-bar:horizontal .track { -fx-background-color: rgba(255,255,255,0.02); -fx-border-color: transparent; -fx-background-radius: 0; }"
            + ".table-view .scroll-bar:vertical .thumb, .table-view .scroll-bar:horizontal .thumb { -fx-background-color: linear-gradient(to bottom, #8a2387, #e94057); -fx-background-radius: 5em; }"
            + ".table-view .scroll-bar:vertical .thumb:hover, .table-view .scroll-bar:horizontal .thumb:hover { -fx-background-color: linear-gradient(to bottom, #00f2fe, #4facfe); }"
            + ".table-view .corner { -fx-background-color: transparent; }";
        
        scene.getStylesheets().add("data:text/css;charset=utf-8," + URLEncoder.encode(css, "UTF-8").replace("+", "%20"));

        displayThreats(controller.getStoredAdvisories());

        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void handleQuerySubmission() {
        String query = queryInput.getText();
        if (query.trim().isEmpty()) return;
        
        chatHistoryHtml.append("<div style='margin: 15px 0; text-align: right;'>")
                       .append("<div style='display: inline-block; background: linear-gradient(135deg, rgba(0,242,254,0.15), rgba(79,172,254,0.05)); border: 1px solid rgba(0,242,254,0.2); padding: 12px 18px; border-radius: 18px 18px 4px 18px; color: #ffffff; font-size: 14px; box-shadow: 0 4px 10px rgba(0,0,0,0.2); text-align: left; max-width: 80%;'>")
                       .append("<b style='color: #00f2fe; font-size: 11px; display: block; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 1px;'>You</b>")
                       .append(escapeHtml(query))
                       .append("</div></div>");
        
        queryInput.clear();
        renderWebView();
        
        new Thread(() -> displaySummary(controller.handleNaturalQuery(query))).start();
    }

    private void executeAdvisoryAction(String logMessage, java.util.function.Function<String, String> action) {
        ThreatAdvisory selected = threatTable.getSelectionModel().getSelectedItem();
        if (selected != null) {
            appendSystemLog(logMessage + " for " + selected.getId() + "...");
            new Thread(() -> displaySummary(action.apply(selected.getId()))).start();
        } else {
            showError("Please select an advisory from the table first.");
        }
    }

    public void displayThreats(List<ThreatAdvisory> threats) {
        Platform.runLater(() -> {
            ObservableList<ThreatAdvisory> data = FXCollections.observableArrayList(threats);
            threatTable.setItems(data);
        });
    }

    public void appendSystemLog(String message) {
        Platform.runLater(() -> {
            chatHistoryHtml.append("<div style='margin: 12px 0; text-align: center;'>")
                           .append("<span style='background: linear-gradient(90deg, rgba(0,242,254,0.08), rgba(233,64,87,0.08)); border: 1px solid rgba(255,255,255,0.08); border-radius: 20px; padding: 6px 16px; font-size: 12px; color: #b0b0c5; display: inline-block; font-style: italic; box-shadow: 0 2px 6px rgba(0,0,0,0.15);'>")
                           .append("<b style='color: #00f2fe; font-style: normal;'>[Orion AI]</b> &nbsp;")
                           .append(escapeHtml(message))
                           .append("</span></div>");
            renderWebView();
        });
    }

    public void displaySummary(String markdownSummary) {
        Platform.runLater(() -> {
            String convertedHtml = convertMarkdownToHtml(markdownSummary);
            chatHistoryHtml.append("<div style='background: linear-gradient(135deg, rgba(255,255,255,0.08), rgba(255,255,255,0.02)); ")
                           .append("border-left: 4px solid #e94057; border-top: 1px solid rgba(255,255,255,0.15); border-right: 1px solid rgba(255,255,255,0.05); border-bottom: 1px solid rgba(255,255,255,0.05); ")
                           .append("padding: 20px; margin: 15px 0; border-radius: 12px; box-shadow: 0 8px 16px rgba(0,0,0,0.25);'>")
                           .append("<b style='color: #e94057; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;'>✨ Orion AI</b><br><br>")
                           .append(convertedHtml)
                           .append("</div>");
            renderWebView();
        });
    }

    public void showError(String message) {
        Platform.runLater(() -> {
            chatHistoryHtml.append("<div style='background: linear-gradient(135deg, rgba(255,76,76,0.15), rgba(255,76,76,0.03)); ")
                           .append("border-left: 4px solid #ff4c4c; border-top: 1px solid rgba(255,76,76,0.2); border-right: 1px solid rgba(255,76,76,0.05); border-bottom: 1px solid rgba(255,76,76,0.05); ")
                           .append("padding: 15px; margin: 15px 0; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.2);'>")
                           .append("<b style='color: #ff4c4c; font-size: 13px; text-transform: uppercase; letter-spacing: 1px;'>⚠️ System Error</b><br><br>")
                           .append("<span style='color: #e0e0e5; font-size: 13.5px;'>").append(escapeHtml(message)).append("</span>")
                           .append("</div>");
            renderWebView();
        });
    }

    private void renderWebView() {
        String fullHtml = "<html><head><style>" +
                "body { font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif; font-size: 14px; background-color: #121024; color: #e0e0e5; padding: 20px; margin: 0; line-height: 1.5; overflow-x: hidden; }" +
                "::-webkit-scrollbar { width: 10px; }" +
                "::-webkit-scrollbar-track { background: rgba(255,255,255,0.02); }" +
                "::-webkit-scrollbar-thumb { background: linear-gradient(to bottom, #8a2387, #e94057); border-radius: 5px; }" +
                "::-webkit-scrollbar-thumb:hover { background: linear-gradient(to bottom, #00f2fe, #4facfe); }" +
                "</style></head><body>" +
                chatHistoryHtml.toString() +
                "</body></html>";
        webEngine.loadContent(fullHtml);
    }

    private void loadCarouselData() {
        String marqueeHtml = "<html><head><style>" +
                "body { background: transparent; margin: 0; padding: 0; font-family: 'Segoe UI', sans-serif; font-size: 12px; color: #a0a0b5; overflow: hidden; }" +
                ".marquee-container { width: 100%; overflow: hidden; white-space: nowrap; box-sizing: border-box; display: flex; align-items: center; background: #0a081a; border-top: 1px solid rgba(255,255,255,0.05); border-bottom: 1px solid rgba(255,255,255,0.05); height: 34px; }" +
                ".marquee { display: inline-block; animation: marquee_anim 80s linear infinite; font-weight: bold; padding-left: 10%; }" +
                ".marquee a { color: #85859e; text-decoration: none; font-weight: bold; margin-right: 180px; transition: color 0.3s; }" +
                ".marquee a:hover { color: #e94057; text-decoration: underline; }" +
                ".marquee span { color: #e94057; font-weight: 900; margin-right: 8px; }" +
                "@keyframes marquee_anim { 0% { transform: translate3d(0, 0, 0); } 100% { transform: translate3d(-50%, 0, 0); } }" + 
                "</style></head><body>" +
                "<div class='marquee-container'>" +
                "<div class='marquee'>" +
                "<span>LATEST INTEL</span> <a href='https://www.cisa.gov/news-events/cybersecurity-advisories'>GitLab Critical Zero-Day Vulnerability Released: Immediate patching is highly recommended for all self-managed instances.</a>" +
                "<span>LATEST INTEL</span> <a href='https://www.nist.gov/cybersecurity'>NIST Releases Updated AI Safety and Risk Management Guidelines: Outlining new standards for operational security.</a>" +
                "<span>LATEST INTEL</span> <a href='https://www.cisa.gov/known-exploited-vulnerabilities-catalog'>CISA KEV Expansion: Federal agencies order urgent triage on 15 newly discovered active system exploits.</a>" +
                "<span>LATEST INTEL</span> <a href='https://www.bleepingcomputer.com/'>Ransomware Attacks Surged 40% Globally in Q3: Financial and healthcare operations remain top targets.</a>" +
                "<span>LATEST INTEL</span> <a href='https://www.cisa.gov/news-events/cybersecurity-advisories'>GitLab Critical Zero-Day Vulnerability Released: Immediate patching is highly recommended for all self-managed instances.</a>" +
                "<span>LATEST INTEL</span> <a href='https://www.nist.gov/cybersecurity'>NIST Releases Updated AI Safety and Risk Management Guidelines: Outlining new standards for operational security.</a>" +
                "<span>LATEST INTEL</span> <a href='https://www.cisa.gov/known-exploited-vulnerabilities-catalog'>CISA KEV Expansion: Federal agencies order urgent triage on 15 newly discovered active system exploits.</a>" +
                "<span>LATEST INTEL</span> <a href='https://www.bleepingcomputer.com/'>Ransomware Attacks Surged 40% Globally in Q3: Financial and healthcare operations remain top targets.</a>" +
                "</div>" +
                "</div>" +
                "</body></html>";
        carouselWebView.getEngine().loadContent(marqueeHtml);
    }

    private String convertMarkdownToHtml(String markdown) {
        if (markdown == null) return "";
        String html = escapeHtml(markdown);
        
        html = html.replaceAll("\\n{3,}", "\n\n");
        html = html.replaceAll("(?m)^###\\s+(.*)$", "<h3 style='color: #ffffff; margin: 0 0 12px 0; font-size: 15.5px; font-weight: 900; text-transform: uppercase; letter-spacing: 1px;'>$1</h3>");
        html = html.replaceAll("\\*\\*(.*?)\\*\\*", "<b style='color: #00f2fe; font-size: 13.5px; display: inline-block; margin-top: 10px; margin-bottom: 2px;'>$1</b>");
        html = html.replaceAll("\\*(.*?)\\*", "<i>$1</i>");
        html = html.replaceAll("(?m)^-\\s+(.*)$", "<li style='margin-left: 18px; margin-bottom: 4px; line-height: 1.4;'>$1</li>");
        html = html.replaceAll("(?m)^\\*\\s+(.*)$", "<li style='margin-left: 18px; margin-bottom: 4px; line-height: 1.4;'>$1</li>");
        html = html.replaceAll("(?m)^>\\s+(.*)$", "<blockquote style='border-left: 3px solid #e94057; margin: 4px 0; padding-left: 12px; color: #b3b3b3;'>$1</blockquote>");
        
        html = html.replace("\n", "<br>");
        html = html.replaceAll("</h3><br>", "</h3>");
        html = html.replaceAll("</b><br>", "</b>"); 
        html = html.replaceAll("</li><br>", "</li>");
        html = html.replaceAll("<br><br><br>", "<br><br>"); 
        
        return html;
    }

    private String escapeHtml(String str) {
        return str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    @Override
    public void onSecurityEvent(String eventType, Object data) {
        Platform.runLater(() -> {
            if ("SYNC_COMPLETE".equals(eventType)) {
                appendSystemLog("Sync completed successfully. " + data + " records processed.");
                displayThreats(controller.getStoredAdvisories());
            } else if ("SYNC_ERROR".equals(eventType)) {
                showError(data.toString());
            }
        });
    }
    
    public static void main(String[] args) { launch(args); }
}