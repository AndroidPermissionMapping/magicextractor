package cispa.permission.mapper.model;

import saarland.cispa.cp.fuzzing.serialization.ContentValue;

public class InsertMagicValues implements FoundMagicValues {
    private final ContentValue contentValue;

    public InsertMagicValues(ContentValue contentValue) {
        this.contentValue = contentValue;
    }

    public ContentValue getContentValue() {
        return contentValue;
    }
}
