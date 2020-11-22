package cispa.permission.mapper.model;

import saarland.cispa.cp.fuzzing.serialization.BundleKey;

import java.util.Objects;
import java.util.Set;

public class CallMethodAndArg implements FoundMagicValues {

    private final CallApiType type;
    private final Set<String> methodMagicEquals;
    private final Set<String> argMagicEquals;
    private final Set<BundleKey> extrasMagicValues;

    public CallMethodAndArg(CallApiType type, Set<String> methodMagicEquals, Set<String> argMagicEquals,
                            Set<BundleKey> extrasMagicValues) {
        this.type = type;
        this.methodMagicEquals = methodMagicEquals;
        this.argMagicEquals = argMagicEquals;
        this.extrasMagicValues = extrasMagicValues;
    }

    public CallApiType getType() {
        return type;
    }

    public Set<String> getMethodMagicEquals() {
        return methodMagicEquals;
    }

    public Set<String> getArgMagicEquals() {
        return argMagicEquals;
    }

    public Set<BundleKey> getExtrasMagicValues() {
        return extrasMagicValues;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CallMethodAndArg that = (CallMethodAndArg) o;
        return methodMagicEquals.equals(that.methodMagicEquals) &&
                argMagicEquals.equals(that.argMagicEquals);
    }

    @Override
    public int hashCode() {
        return Objects.hash(methodMagicEquals, argMagicEquals);
    }

    @Override
    public String toString() {
        return "CallMethodAndArg{" +
                "methodMagicEquals=" + methodMagicEquals +
                ", argMagicEquals=" + argMagicEquals +
                '}';
    }
}
