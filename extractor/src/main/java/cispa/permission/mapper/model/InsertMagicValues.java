package cispa.permission.mapper.model;

import saarland.cispa.cp.fuzzing.serialization.BundleKey;

public class InsertMagicValues implements FoundMagicValues {
    private final BundleKey contentValue;

    public InsertMagicValues(BundleKey contentValue) {
        this.contentValue = contentValue;
    }

    public BundleKey getContentValue() {
        return contentValue;
    }
}
