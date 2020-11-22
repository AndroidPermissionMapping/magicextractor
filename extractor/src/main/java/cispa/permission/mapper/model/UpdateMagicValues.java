package cispa.permission.mapper.model;

import saarland.cispa.cp.fuzzing.serialization.BundleKey;

import java.util.Set;

public class UpdateMagicValues implements FoundMagicValues {
    private final Set<BundleKey> contentValues;
    private final Set<String> selections;

    public UpdateMagicValues(Set<BundleKey> contentValues, Set<String> selections) {
        this.contentValues = contentValues;
        this.selections = selections;
    }

    public Set<BundleKey> getContentValues() {
        return contentValues;
    }

    public Set<String> getSelections() {
        return selections;
    }
}
