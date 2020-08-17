package cispa.permission.mapper;

import org.json.JSONArray;
import org.json.JSONObject;
import soot.SootMethod;
import soot.Value;
import soot.ValueBox;
import soot.jimple.*;
import soot.jimple.internal.ImmediateBox;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class Utils {

    static BufferedWriter f = null;
    static boolean first = true;
    static final Integer x = 0;

    public static Object immediate(Value val){
        if (val instanceof StringConstant)
            return ((StringConstant)val).value;
        else if (val instanceof NullConstant)
            return null;
        else if (val instanceof IntConstant)
            return ((IntConstant) val).value;
        else if (val instanceof LongConstant)
            return ((LongConstant) val).value;
        throw new IllegalArgumentException("no immediate " + val.getClass().toString());
    }

    public static String immediateString(Value val){
        if (val instanceof StringConstant)
            return ((StringConstant)val).value;
        throw new IllegalArgumentException("no stringconstant " + val.getClass().toString());
    }

    public static String immediateString(ValueBox b){
        if (b instanceof ImmediateBox){
            return immediateString(b.getValue());
        }
        throw new IllegalArgumentException("no immediate box " + b.toString());
    }

    public static Object immediate(ValueBox b){
        if (b instanceof ImmediateBox){
            return immediate(b.getValue());
        }
        throw new IllegalArgumentException("no immediate box " + b.toString());
    }

    public static void write(String s){
        synchronized (x) {
            if (f != null) {
                try {
                    if (!first) {
                        f.write(",\n");
                    }
                    first = false;
                    f.write(s);
                    f.flush();
                    System.out.println(s);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void result(SootMethod m, ArrayList<String> matches, String mode, String param) {
        if (matches.isEmpty()){
            return;
        }
        JSONObject obj = new JSONObject();
        obj.put("magic", matches);
        obj.put("param", param);
        obj.put("analysis", mode);
        obj.put("method", m.getDeclaringClass().toString()+"."+m.getName());
        write(obj.toString());
    }



    public static void result(SootMethod m, JSONArray matches, String mode) {
        JSONObject obj = new JSONObject();
        obj.put("results", matches);
        obj.put("analysis", mode);
        obj.put("method", m.getDeclaringClass().toString()+"."+m.getName());
        write(obj.toString());

    }

    public static void result(SootMethod m, JSONObject matches, String mode, String param) {
        JSONObject obj = new JSONObject();
        obj.put("magic", matches);
        obj.put("param", param);
        obj.put("analysis", mode);
        obj.put("method", m.getDeclaringClass().toString()+"."+m.getName());
        write(obj.toString());
    }
    public static void result(SootMethod m, JSONArray matches, String mode, String param) {
        JSONObject obj = new JSONObject();
        obj.put("results", matches);
        obj.put("param", param);
        obj.put("analysis", mode);
        obj.put("method", m.getDeclaringClass().toString()+"."+m.getName());
        write(obj.toString());
    }
}
