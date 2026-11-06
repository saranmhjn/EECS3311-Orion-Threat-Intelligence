package ca.yorku.eecs3311.orion.observer;

/**
 * Interface for the Observer Pattern.
 * Allows the GUI or CLI to listen for background events (like AI completion or data syncs)
 * without tightly coupling the presentation layer to the deterministic controller.
 */
public interface SecurityObserver {
    
    /**
     * Called by the AgentController when a significant event occurs.
     * 
     * @param eventType A string describing the event (e.g., "SYNC_COMPLETE", "RISK_CORRELATED").
     * @param data Optional payload containing the event results.
     */
    /*@ 
      @ requires eventType != null && eventType.length() > 0; 
      @*/
    void onSecurityEvent(String eventType, Object data);
}