package cispa.permission.mapper.model;

import java.util.Set;

public class DeleteMagicValues implements FoundMagicValues {
    private final Set<String> selectionStrings;

    public DeleteMagicValues(Set<String> selectionStrings) {
        this.selectionStrings = selectionStrings;
    }

    public Set<String> getSelectionStrings() {
        return selectionStrings;
    }
}
