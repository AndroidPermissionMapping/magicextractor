package cispa.permission.mapper.magic;

import org.json.JSONObject;
import soot.Type;

import java.util.Objects;

public class BundleElement{
    public final Type type;
    public final String name;
    public final Object value;
    public final boolean has_default_value;

    public BundleElement(Type type, String name){
        this.type = type;
        this.name = name;
        this.value = null;
        has_default_value = false;
    }
    public BundleElement(Type type, String name, Object value){
        this.value = value;
        this.type = type;
        this.name = name;
        has_default_value = true;
    }
    public JSONObject toJSON(){
        JSONObject param_obj = new JSONObject();
        param_obj.put("name", name);
        param_obj.put("type", type);
        if (has_default_value)
            param_obj.put("default", value);
        return param_obj;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BundleElement that = (BundleElement) o;
        return has_default_value == that.has_default_value &&
                Objects.equals(type, that.type) &&
                Objects.equals(name, that.name) &&
                Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, name, value, has_default_value);
    }
}