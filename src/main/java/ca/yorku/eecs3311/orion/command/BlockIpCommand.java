package ca.yorku.eecs3311.orion.command;

/**
 * Concrete command to block a malicious IP address.
 */
public class BlockIpCommand implements SecurityCommand {
    
    private String ipAddress;

    /*@ public invariant ipAddress != null && ipAddress.length() > 0; @*/

    /*@
      @ requires ipAddress != null && ipAddress.length() > 0;
      @ ensures this.ipAddress == ipAddress;
      @*/
    public BlockIpCommand(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    @Override
    public boolean execute() {
        // In a live production environment, this would interface with OS firewalls.
        System.out.println("EXECUTED: Blocking IP Address -> " + ipAddress);
        return true;
    }

    @Override
    public boolean undo() {
        System.out.println("ROLLED BACK: Unblocking IP Address -> " + ipAddress);
        return true;
    }

    @Override
    public String getDescription() {
        return "Block IP: " + ipAddress;
    }
}