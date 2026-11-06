package ca.yorku.eecs3311.orion.util;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts and deduplicates structured Indicators of Compromise (IoCs) 
 * from unstructured text using deterministic regular expressions.
 * Fulfills Feature F06 (Structured Indicator of Compromise Extraction).
 */
public class IocExtractor {

    // Standard IPv4 Regex Pattern
    private static final Pattern IP_PATTERN = Pattern.compile(
        "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"
    );

    // Standard MD5 / SHA-256 Hash Pattern
    private static final Pattern HASH_PATTERN = Pattern.compile(
        "\\b[a-fA-F0-9]{32}\\b|\\b[a-fA-F0-9]{64}\\b"
    );

    /**
     * Extracts unique IP addresses and hashes from unstructured threat text.
     * 
     * @param unstructuredText The raw text from an advisory or threat report.
     * @return A deduplicated list of found IoCs.
     */
    /*@ 
      @ requires unstructuredText != null;
      @ ensures \result != null;
      @*/
    public List<String> extractIocs(String unstructuredText) {
        Set<String> iocs = new HashSet<>();

        if (unstructuredText == null || unstructuredText.isEmpty()) {
            return new ArrayList<>(iocs);
        }

        // Match IP addresses
        Matcher ipMatcher = IP_PATTERN.matcher(unstructuredText);
        while (ipMatcher.find()) {
            iocs.add("IP: " + ipMatcher.group());
        }

        // Match File Hashes
        Matcher hashMatcher = HASH_PATTERN.matcher(unstructuredText);
        while (hashMatcher.find()) {
            iocs.add("Hash: " + hashMatcher.group());
        }

        return new ArrayList<>(iocs);
    }
}