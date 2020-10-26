package cispa.permission.mapper.magic;

import org.json.JSONArray;
import org.json.JSONObject;
import soot.Local;
import soot.SootMethod;

import java.util.HashSet;

public class State{
    public final Local local;
    public final String method;
    public final HashSet<State> children = new HashSet<>();
    public final HashSet<String> passed_to = new HashSet<>();
    public final HashSet<String> query_parameters = new HashSet<>();
    public final HashSet<String> magic_equals = new HashSet<>();
    public final HashSet<String> magic_split = new HashSet<>();
    public final HashSet<String> magic_equals_ignorecase = new HashSet<>();
    public final HashSet<String> magic_substring = new HashSet<>();
    public final HashSet<String> magic_regex = new HashSet<>();
    public final HashSet<BundleElement> bundle_elements = new HashSet<>();
    public final HashSet<BundleElement> cv_elements = new HashSet<>();
    public boolean eaten = false;

    public State(Local l, SootMethod m){
        this.local = l;
        this.method = m.getSignature();
    }

    public String toJson() {

        return null;
    }

    public JSONObject toJSON(){
        JSONObject state_obj = new JSONObject();
        JSONObject param_obj = new JSONObject();
        param_obj.put("name", local.getName());
        param_obj.put("type", local.getType());
        state_obj.put("param", param_obj);
        //state_obj.put("defined_in", method);
        if (!bundle_elements.isEmpty()) {
            JSONArray bundle_elems = new JSONArray();
            for (BundleElement elem : bundle_elements) {
                bundle_elems.put(elem.toJSON());
            }
            state_obj.put("bundle", bundle_elems);
        }
        if (!cv_elements.isEmpty()) {
            JSONArray bundle_elems = new JSONArray();
            for (BundleElement elem : cv_elements) {
                bundle_elems.put(elem.toJSON());
            }
            state_obj.put("ContentValues", bundle_elems);
        }
        if (!magic_equals.isEmpty()){
            JSONArray magic_elems = new JSONArray();
            for (String elem : magic_equals) {
                magic_elems.put(elem);
            }
            state_obj.put("magic_equals", magic_elems);
        }
        if (!query_parameters.isEmpty()){
            JSONArray magic_elems = new JSONArray();
            for (String elem : query_parameters) {
                magic_elems.put(elem);
            }
            state_obj.put("query_parameters", magic_elems);
        }
        if (!magic_equals_ignorecase.isEmpty()){
            JSONArray magic_elems = new JSONArray();
            for (String elem : magic_equals_ignorecase) {
                magic_elems.put(elem);
            }
            state_obj.put("magic_equals_ignorecase", magic_elems);
        }
        if (!magic_split.isEmpty()){
            JSONArray magic_elems = new JSONArray();
            for (String elem : magic_split) {
                magic_elems.put(elem);
            }
            state_obj.put("magic_split", magic_elems);
        }
        if (!magic_substring.isEmpty()){
            JSONArray magic_elems = new JSONArray();
            for (String elem : magic_substring) {
                magic_elems.put(elem);
            }
            state_obj.put("magic_substring", magic_elems);
        }
        if (!magic_regex.isEmpty()){
            JSONArray magic_elems = new JSONArray();
            for (String elem : magic_regex) {
                magic_elems.put(elem);
            }
            state_obj.put("magic_regex", magic_elems);
        }
        if (!passed_to.isEmpty()){
            JSONArray passed_elems = new JSONArray();
            for (String elem : passed_to) {
                passed_elems.put(elem);
            }
            //state_obj.put("passed_to", passed_elems);
        }
        return state_obj;
    }

    public void merge(State s){
        passed_to.add(s.method);
        passed_to.addAll(s.passed_to);
        query_parameters.addAll(s.query_parameters);
        magic_equals.addAll(s.magic_equals);
        magic_split.addAll(s.magic_split);
        magic_equals_ignorecase.addAll(s.magic_equals_ignorecase);
        magic_substring.addAll(s.magic_substring);
        magic_regex.addAll(s.magic_regex);
        bundle_elements.addAll(s.bundle_elements);
        cv_elements.addAll(s.cv_elements);
    }

    public void eatChildren(){
        if (eaten){
            //throw new RuntimeException("loop!");  // TODO: maybe there is something better than that
            return;
        }
        eaten = true;
        for (State child: children) {
            child.eatChildren();
            this.merge(child);
        }
    }

    public void addParents(Iterable<State> states){
        for (State state: states){
            //System.out.println(state.local.getName() + " -> " + local.getName());
            state.children.add(this);
        }
    }

    @Override
    public String toString() {
        return "State{" +
                "local=" + local +
                ", method='" + method + '\'' +
                ", children=" + children +
                ", passed_to=" + passed_to +
                ", query_parameters=" + query_parameters +
                ", magic_equals=" + magic_equals +
                ", magic_split=" + magic_split +
                ", magic_equals_ignorecase=" + magic_equals_ignorecase +
                ", magic_substring=" + magic_substring +
                ", magic_regex=" + magic_regex +
                ", bundle_elements=" + bundle_elements +
                ", cv_elements=" + cv_elements +
                ", eaten=" + eaten +
                '}';
    }
}
