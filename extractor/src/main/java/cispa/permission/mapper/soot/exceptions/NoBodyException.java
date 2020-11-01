package cispa.permission.mapper.soot.exceptions;

import soot.SootMethod;

public class NoBodyException extends RuntimeException {
    public NoBodyException(SootMethod m) {
        super("no method source set for method: " + m.getSignature());
    }
}
