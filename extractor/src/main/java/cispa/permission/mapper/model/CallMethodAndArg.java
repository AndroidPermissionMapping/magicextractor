package cispa.permission.mapper.model;

import java.util.Objects;
import java.util.Set;

public class CallMethodAndArg implements FoundMagicValues {
    private final Set<String> methodMagicEquals;
    private final Set<String> argMagicEquals;

    public CallMethodAndArg(Set<String> methodMagicEquals, Set<String> argMagicEquals) {
        this.methodMagicEquals = methodMagicEquals;
        this.argMagicEquals = argMagicEquals;
    }

    public Set<String> getMethodMagicEquals() {
        return methodMagicEquals;
    }

    public Set<String> getArgMagicEquals() {
        return argMagicEquals;
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
