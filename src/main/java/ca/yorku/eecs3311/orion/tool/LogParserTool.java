package ca.yorku.eecs3311.orion.tool;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Concrete strategy tool for parsing internal audit logs.
 * Fulfills Feature F04 (Insider Risk Log Correlation)[cite: 5].
 */
public class LogParserTool implements Tool {

    @Override
    public String getName() {
        return "LogParserTool";
    }

    @Override
    public Object execute(Map<String, Object> args) throws Exception {
        String filePath = (String) args.get("filePath");
        List<String> anomalies = new ArrayList<>();

        if (filePath == null || filePath.isEmpty()) {
            // Default simulation fallback if no file path is explicitly passed
            anomalies.add("ANOMALY: Bulk data export detected from service account.");
            return anomalies;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                String lowerLine = line.toLowerCase();
                if (lowerLine.contains("fail") || lowerLine.contains("unauthorized") || 
                    lowerLine.contains("bulk") || lowerLine.contains("anomaly")) {
                    anomalies.add("ANOMALY DETECTED: " + line);
                }
            }
        } catch (Exception e) {
            throw new Exception("Log parsing failed: " + e.getMessage());
        }

        return anomalies;
    }
}