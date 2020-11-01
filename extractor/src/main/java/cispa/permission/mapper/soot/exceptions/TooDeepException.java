package cispa.permission.mapper.soot.exceptions;

import soot.SootMethod;

public class TooDeepException extends RuntimeException {
    public TooDeepException(SootMethod m) {
        super("max recursion depth reached at method: " + m.getSignature());
    }
}
