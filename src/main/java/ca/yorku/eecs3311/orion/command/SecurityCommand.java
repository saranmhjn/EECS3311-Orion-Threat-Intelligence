package ca.yorku.eecs3311.orion.command;

/**
 * Interface for executable security remediation actions.
 * Fulfills the Command Pattern requirement in the Stage 1 UML diagram.
 */
public interface SecurityCommand {
    
    /**
     * Executes the security action.
     * @return true if execution was successful, false otherwise.
     */
    /*@ ensures \result == true || \result == false; @*/
    boolean execute();
    
    /**
     * Reverts the security action.
     * @return true if rollback was successful.
     */
    /*@ ensures \result == true || \result == false; @*/
    boolean undo();
    
    /**
     * Gets a human-readable description of the command.
     */
    /*@ ensures \result != null; @*/
    String getDescription();
}