package cispa.permission.mapper.model;

import java.util.List;
import java.util.Set;

public class ContentProviderQuery implements FoundMagicValues {

    private final List<Set<String>> args;

    public ContentProviderQuery(List<Set<String>> args) {
        this.args = args;
    }

    public boolean isApi1Implementation() {
        return args.size() == 4;
    }

    public List<Set<String>> getArgs() {
        return args;
    }

}
