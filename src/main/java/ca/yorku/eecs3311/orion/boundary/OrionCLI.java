package ca.yorku.eecs3311.orion.boundary;

import ca.yorku.eecs3311.orion.controller.AgentController;
import ca.yorku.eecs3311.orion.database.DatabaseManager;
import ca.yorku.eecs3311.orion.model.ThreatAdvisory;

import java.util.List;
import java.util.Scanner;

/**
 * Command Line Interface (CLI) workspace for Orion Threat Intelligence.
 * Features an elite Metasploit-inspired ASCII banner and optimized truncated table views.
 */
public class OrionCLI {

    // Corrected ANSI Escape Codes for Hacker Terminal Styling
    private static final String RESET = "\u001b[0m";
    private static final String CYAN = "\u001b[36m";
    private static final String RED = "\u001b[31m";
    private static final String GREEN = "\u001b[32m";
    private static final String YELLOW = "\u001b[33m";
    private static final String BOLD = "\u001b[1m";

    private AgentController controller;
    private final Scanner scanner;

    public OrionCLI() {
        this.scanner = new Scanner(System.in);
        try {
            DatabaseManager dbManager = new DatabaseManager();
            this.controller = new AgentController(dbManager);
        } catch (java.sql.SQLException e) {
            System.err.println("[!] Critical Database Error: Failed to initialize SQLite database.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void start() {
        printBanner();
        boolean running = true;

        while (running) {
            System.out.print(CYAN + "orion" + RED + "(cti)" + RESET + "> ");
            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("exit") || input.equalsIgnoreCase("quit")) {
                System.out.println(YELLOW + "[*] Terminating Orion CLI session. Stay secure." + RESET);
                running = false;
                break;
            }

            handleCommand(input);
        }
    }

    private void handleCommand(String command) {
        String[] parts = command.split("\\s+", 2);
        String cmd = parts[0].toLowerCase();
        String arg = parts.length > 1 ? parts[1] : "";

        switch (cmd) {
            case "help":
            case "?":
                printHelp();
                break;
            case "list":
                listAdvisories(arg);
                break;
            case "sync":
                syncFeeds(arg);
                break;
            case "summarize":
                if (arg.isEmpty()) {
                    System.out.println(RED + "[!] Error: Specify a CVE ID (e.g., summarize CVE-2026-97229)" + RESET);
                } else {
                    System.out.println(YELLOW + "[*] Querying Orion AI for summary on " + arg + "..." + RESET);
                    String summary = controller.summarizeAdvisory(arg);
                    System.out.println("\n" + GREEN + "=== AI EXECUTIVE SUMMARY ===" + RESET + "\n" + summary);
                }
                break;
            case "mitigate":
                if (arg.isEmpty()) {
                    System.out.println(RED + "[!] Error: Specify a CVE ID." + RESET);
                } else {
                    System.out.println(YELLOW + "[*] Generating mitigation playbook for " + arg + "..." + RESET);
                    String playbook = controller.generateMitigationPlaybook(arg, "Standard Enterprise Environment");
                    System.out.println("\n" + GREEN + "=== MITIGATION PLAYBOOK ===" + RESET + "\n" + playbook);
                }
                break;
            case "correlate":
                if (arg.isEmpty()) {
                    System.out.println(RED + "[!] Error: Provide a path to a log file." + RESET);
                } else {
                    System.out.println(YELLOW + "[*] Scanning audit log: " + arg + "..." + RESET);
                    List<String> anomalies = controller.correlateLogs(arg);
                    System.out.println("\n" + GREEN + "=== LOG CORRELATION RESULTS ===" + RESET);
                    if (anomalies.isEmpty()) {
                        System.out.println("No anomalies or threat signatures detected.");
                    } else {
                        anomalies.forEach(a -> System.out.println(" ⚡ " + a));
                    }
                }
                break;
            case "iocs":
                if (arg.isEmpty()) {
                    System.out.println(RED + "[!] Error: Provide text containing IOCs." + RESET);
                } else {
                    List<String> iocs = controller.extractIocsFromText(arg);
                    System.out.println("\n" + GREEN + "=== EXTRACTED IOCs ===" + RESET);
                    iocs.forEach(i -> System.out.println(" 🎯 " + i));
                }
                break;
            case "query":
                if (arg.isEmpty()) {
                    System.out.println(RED + "[!] Error: Enter a natural language question." + RESET);
                } else {
                    System.out.println(YELLOW + "[*] Orion AI processing query..." + RESET);
                    String response = controller.handleNaturalQuery(arg);
                    System.out.println("\n" + GREEN + "=== ORION AI RESPONSE ===" + RESET + "\n" + response);
                }
                break;
            case "clear":
                printBanner();
                break;
            default:
                System.out.println(RED + "[!] Unknown command. Type 'help' for available commands." + RESET);
        }
    }

    private void listAdvisories(String limitArg) {
        List<ThreatAdvisory> allAdvisories = controller.getStoredAdvisories();
        if (allAdvisories.isEmpty()) {
            System.out.println(YELLOW + "[*] Database is empty. Use 'sync cisa' or 'sync nist' to ingest feeds." + RESET);
            return;
        }

        int limit = 15;
        try {
            if (!limitArg.isEmpty()) {
                limit = Integer.parseInt(limitArg);
            }
        } catch (NumberFormatException ignored) {}

        int displayCount = Math.min(limit, allAdvisories.size());

        System.out.println(CYAN + String.format("\nShowing %d of %d cached advisories (Use 'list <number>' to see more):", displayCount, allAdvisories.size()) + RESET);
        System.out.println(String.format("%-15s | %-15s | %-12s | %-10s", "CVE ID", "VENDOR", "PRODUCT", "SEVERITY"));
        System.out.println("-".repeat(65));

        for (int i = 0; i < displayCount; i++) {
            ThreatAdvisory adv = allAdvisories.get(i);
            String sev = safeStr(adv.getSeverity(), 10);
            String colorSev = sev.equalsIgnoreCase("CRITICAL") ? RED + sev + RESET : sev;

            System.out.println(String.format("%-15s | %-15s | %-12s | %s",
                    adv.getId(),
                    safeStr(adv.getVendor(), 15),
                    safeStr(adv.getProduct(), 12),
                    colorSev));
        }
    }

    private void syncFeeds(String source) {
        if (source.equalsIgnoreCase("cisa")) {
            System.out.println(YELLOW + "[*] Synchronizing CISA KEV feed..." + RESET);
            controller.syncFeeds("CISA");
            System.out.println(GREEN + "[+] CISA KEV sync complete." + RESET);
        } else if (source.equalsIgnoreCase("nist")) {
            System.out.println(YELLOW + "[*] Synchronizing NIST NVD feed..." + RESET);
            controller.syncFeeds("NIST");
            System.out.println(GREEN + "[+] NIST NVD sync complete." + RESET);
        } else {
            System.out.println(RED + "[!] Specify source: 'sync cisa' or 'sync nist'" + RESET);
        }
    }

    private String safeStr(String val, int maxLen) {
        if (val == null) return "N/A";
        return val.length() > maxLen ? val.substring(0, maxLen - 3) + "..." : val;
    }

    private void printBanner() {
        int totalAdvisories = controller.getStoredAdvisories().size();
        System.out.println(RED + BOLD);
        System.out.println("   ____       _             ");
        System.out.println("  / __ \\     (_)            ");
        System.out.println(" | |  | |_ __ _  ___  _ __  ");
        System.out.println(" | |  | | '__| |/ _ \\| '_ \\ ");
        System.out.println(" | |__| | |  | | (_) | | | |");
        System.out.println("  \\____/|_|  |_|\\___/|_| |_|");
        System.out.println(CYAN + "  [::] Cyber Threat Intelligence & AI Agent Framework [::]");
        System.out.println(YELLOW + "       Active Cached Advisories: " + totalAdvisories);
        System.out.println(RESET);
        System.out.println("Type 'help' or '?' for available commands, or 'exit' to quit.\n");
    }

    private void printHelp() {
        System.out.println(GREEN + "\n--- ORION CLI COMMAND REFERENCE ---" + RESET);
        System.out.println("  list [limit]         - Display truncated threat advisories (default: 15)");
        System.out.println("  sync <cisa|nist>     - Ingest latest CVE feeds from CISA or NIST");
        System.out.println("  summarize <CVE-ID>   - Generate an AI executive summary for a specific CVE");
        System.out.println("  mitigate <CVE-ID>    - Generate an enterprise mitigation playbook");
        System.out.println("  correlate <filepath> - Scan an audit log file for threat signatures");
        System.out.println("  iocs <text>          - Extract defanged IPs, hashes, and domains from text");
        System.out.println("  query <question>     - Ask Orion AI a natural language security question");
        System.out.println("  clear                - Clear screen and reload banner");
        System.out.println("  exit                 - Terminate the CLI session");
    }

    public static void main(String[] args) {
        new OrionCLI().start();
    }
}