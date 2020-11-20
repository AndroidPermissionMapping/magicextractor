package cispa.permission.mapper;

import soot.Value;
import soot.ValueBox;
import soot.jimple.IntConstant;
import soot.jimple.LongConstant;
import soot.jimple.NullConstant;
import soot.jimple.StringConstant;
import soot.jimple.internal.ImmediateBox;

public class Utils {

    public static Object immediate(Value val) {
        if (val instanceof StringConstant)
            return ((StringConstant) val).value;
        else if (val instanceof NullConstant)
            return null;
        else if (val instanceof IntConstant)
            return ((IntConstant) val).value;
        else if (val instanceof LongConstant)
            return ((LongConstant) val).value;
        throw new IllegalArgumentException("no immediate " + val.getClass().toString());
    }

    public static String immediateString(Value val) {
        if (val instanceof StringConstant)
            return ((StringConstant) val).value;
        throw new IllegalArgumentException("no stringconstant " + val.getClass().toString());
    }

    public static String immediateString(ValueBox b) {
        if (b instanceof ImmediateBox) {
            return immediateString(b.getValue());
        }
        throw new IllegalArgumentException("no immediate box " + b.toString());
    }

    public static Object immediate(ValueBox b) {
        if (b instanceof ImmediateBox) {
            return immediate(b.getValue());
        }
        throw new IllegalArgumentException("no immediate box " + b.toString());
    }
}
