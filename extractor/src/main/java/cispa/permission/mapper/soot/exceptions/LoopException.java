package cispa.permission.mapper.soot.exceptions;

import soot.SootMethod;

public class LoopException extends RuntimeException {
    public LoopException(SootMethod m) {
        super("Loop at method: " + m.getSignature());
    }
}
