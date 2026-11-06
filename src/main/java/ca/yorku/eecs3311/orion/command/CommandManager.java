package ca.yorku.eecs3311.orion.command;

import java.util.Stack;

/**
 * Invoker class that executes commands and maintains a history stack for undo operations.
 * Ensures human-in-the-loop safety for all AI-generated mitigation strategies.
 */
public class CommandManager {
    
    private Stack<SecurityCommand> history;

    /*@ public invariant history != null; @*/

    /*@ ensures this.history != null; @*/
    public CommandManager() {
        this.history = new Stack<>();
    }

    /**
     * Executes a command and pushes it to the history stack if successful.
     */
    /*@
      @ requires cmd != null;
      @ ensures \result == true ==> history.contains(cmd);
      @*/
    public boolean invoke(SecurityCommand cmd) {
        boolean success = cmd.execute();
        if (success) {
            history.push(cmd);
        }
        return success;
    }

    /**
     * Pops the most recent command off the stack and reverses its effects.
     */
    /*@ ensures \result == true || \result == false; @*/
    public boolean undoLast() {
        if (!history.isEmpty()) {
            SecurityCommand cmd = history.pop();
            return cmd.undo();
        }
        System.out.println("No commands available to undo.");
        return false;
    }
}