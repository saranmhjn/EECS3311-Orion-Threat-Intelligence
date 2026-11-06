package ca.yorku.eecs3311.orion.util;

import org.junit.jupiter.api.Test;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for deterministic Indicators of Compromise (IoC) extraction.
 * Verifies Feature F06.
 */
public class IocExtractorTest {

    @Test
    public void testExtractIocsSuccessfully() {
        IocExtractor extractor = new IocExtractor();
        String sampleText = "The threat actor utilized IP 192.168.1.50 for C2 traffic " +
                            "and dropped malware with hash 5d41402abc4b2a76b9719d911017c592.";

        List<String> iocs = extractor.extractIocs(sampleText);

        assertNotNull(iocs, "Extracted IoCs list should not be null.");
        assertEquals(2, iocs.size(), "Should find exactly two unique IoCs (1 IP and 1 hash).");
        
        assertTrue(iocs.stream().anyMatch(i -> i.contains("192.168.1.50")), "Should contain the extracted IP address.");
        assertTrue(iocs.stream().anyMatch(i -> i.contains("5d41402abc4b2a76b9719d911017c592")), "Should contain the extracted hash.");
    }

    @Test
    public void testExtractIocsWithEmptyText() {
        IocExtractor extractor = new IocExtractor();
        List<String> iocs = extractor.extractIocs("");

        assertNotNull(iocs, "Result for empty text should still be a non-null empty list.");
        assertTrue(iocs.isEmpty(), "No IoCs should be found in empty text.");
    }
}