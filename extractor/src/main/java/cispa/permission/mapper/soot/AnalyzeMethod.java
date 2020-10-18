package cispa.permission.mapper.soot;

import cispa.permission.mapper.Utils;
import cispa.permission.mapper.magic.BundleElement;
import cispa.permission.mapper.magic.State;
import org.json.JSONArray;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JAssignStmt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

public class AnalyzeMethod {

    public void analyze(SootMethod m){
        analyzeRefs(m);
    }



    private ArrayList<State> analyzeRefsRecursive(SootMethod call, int height) {
        //System.out.println("Analyzing " + call.getName());
        if (!call.hasActiveBody()) {
            System.out.println("no active body for: " + call.toString());
            return new ArrayList<>();
        }
        JimpleBody body = (JimpleBody) call.retrieveActiveBody();
        UnitPatchingChain units = body.getUnits();
        HashMap<Local, State> states = new HashMap<>();
        for (Local l: body.getParameterLocals()){
            states.put(l, new State(l, call));
        }
        for (Unit bx: units){
            Stmt s = (Stmt) bx;
            if (s instanceof JAssignStmt) {
                Value right = ((JAssignStmt) s).rightBox.getValue();
                Value left = ((JAssignStmt) s).leftBox.getValue();
                if (right instanceof VirtualInvokeExpr){
                    Value base = ((VirtualInvokeExpr) right).getBase();
                    SootMethod method = ((VirtualInvokeExpr)right).getMethod();
                    HashSet<Value> params = new HashSet<>();
                    for (Value arg :((VirtualInvokeExpr) right).getArgs()){
                        if(states.containsKey(arg)){
                            params.add(arg);
                        }
                    }
                    if (!params.isEmpty()) {
                        String signature = method.getSignature();
                        switch (signature) {
                            case "<java.lang.String: boolean equals(java.lang.Object)>": {
                                System.out.println("EQUALS " +  base.toString());
                                State state = states.get(((VirtualInvokeExpr) right).getArg(0));
                                if (base instanceof StringConstant)
                                    state.magic_equals.add(Utils.immediateString(base));
                            }
                            break;
                            default:{
                                HashMap<Integer, Value> args_mapping = new HashMap<>();
                                int i = 0;
                                for (Value arg: ((VirtualInvokeExpr) right).getArgs()){
                                    if (states.containsKey(arg)){
                                        args_mapping.put(i, arg);
                                    }
                                    i++;
                                }
                                if (!args_mapping.isEmpty()) {
                                    if (height <= 0){
                                        System.out.println(call.toString() + ": max recursion depth reached");
                                    }
                                    else {
                                        ArrayList<State> result = analyzeRefsRecursive(method, height - 1);
                                        for (i = 0; i < result.size(); i++) {
                                            if (args_mapping.containsKey(i)) {
                                                Value arg = args_mapping.get(i);
                                                states.get(arg).merge(result.get(i));
                                                //System.out.println(result.get(i).toString() + " : " + arg);
                                            }
                                        }
                                    }
                                }
                            }

                                System.out.println("unknown signature '" + signature + "' (params: " + params.toString() + ")");

                        }
                    }
                    if (states.containsKey(base)){
                        State state = states.get(base);
                        switch (base.getType().toString()){
                            case "android.os.Bundle": {
                                int args_count = ((VirtualInvokeExpr) right).getArgCount();
                                if (args_count == 2) {
                                    if (((VirtualInvokeExpr) right).getArg(0) instanceof StringConstant)
                                        state.bundle_elements.add(new BundleElement(method.getReturnType(), Utils.immediateString(((VirtualInvokeExpr) right).getArgBox(0)), Utils.immediate(((VirtualInvokeExpr) right).getArgBox(1))));
                                }
                                else if (args_count == 1) {
                                    if (((VirtualInvokeExpr) right).getArg(0) instanceof StringConstant)
                                        state.bundle_elements.add(new BundleElement(method.getReturnType(), Utils.immediateString(((VirtualInvokeExpr) right).getArgBox(0))));
                                }
                                else
                                    System.out.println("arg count? " + right);
                            }
                                break;
                            case "android.content.ContentValues": {
                                if (((VirtualInvokeExpr) right).getMethod().getName().startsWith("get")) {
                                    int args_count = ((VirtualInvokeExpr) right).getArgCount();
                                    if (args_count == 1) {
                                        if (((VirtualInvokeExpr) right).getArg(0) instanceof StringConstant)
                                            state.cv_elements.add(new BundleElement(method.getReturnType(), Utils.immediateString(((VirtualInvokeExpr) right).getArgBox(0))));
                                    }
                                    else
                                        System.out.println("arg count? " + right);
                                }
                            }
                                break;
                            case "java.lang.String": {
                                String signature = method.getSignature();
                                switch (signature) {
                                    case "<java.lang.String: boolean equals(java.lang.Object)>":
                                        if (((VirtualInvokeExpr) right).getArg(0) instanceof StringConstant)
                                            state.magic_equals.add(Utils.immediateString(((VirtualInvokeExpr) right).getArgBox(0)));
                                        break;
                                    case "<java.lang.String: boolean equalsIgnoreCase(java.lang.String)>":
                                        if (((VirtualInvokeExpr) right).getArg(0) instanceof StringConstant)
                                            state.magic_equals_ignorecase.add(Utils.immediateString(((VirtualInvokeExpr) right).getArgBox(0)));
                                        break;
                                    case "<java.lang.String: java.lang.String[] split(java.lang.String)>":
                                        if (((VirtualInvokeExpr) right).getArg(0) instanceof StringConstant)
                                            state.magic_split.add(Utils.immediateString(((VirtualInvokeExpr) right).getArgBox(0)));
                                        break;
                                    default:
                                        System.out.println("unknown signature" + signature);
                                }
                            }
                                break;
                            case "android.net.Uri": {
                                String signature = method.getSignature();
                                switch (signature) {
                                    case "<android.net.Uri: java.lang.String getQueryParameter(java.lang.String)>":
                                        if (((VirtualInvokeExpr) right).getArg(0) instanceof StringConstant)
                                            state.query_parameters.add(Utils.immediateString(((VirtualInvokeExpr) right).getArgBox(0)));
                                        break;
                                    default:
                                        System.out.println("unknown signature" + signature);
                                    }
                                }
                                break;
                            default:
                                System.out.println("unknown base type: " + base.getType().toString());
                                System.out.println(right);
                        }
//                        System.out.println(right);
                    }
                }
                else if (right instanceof SpecialInvokeExpr){
                    HashMap<Integer, Value> args_mapping = new HashMap<>();
                    int i = 0;
                    for (Value arg: ((SpecialInvokeExpr) right).getArgs()){
                        if (states.containsKey(arg)){
                            args_mapping.put(i, arg);
                        }
                        i++;
                    }
                    if (!args_mapping.isEmpty()) {
                        if (height <= 0){
                            System.out.println(call.toString() + ": max recursion depth reached");
                        }
                        else {
                            ArrayList<State> result = analyzeRefsRecursive(((SpecialInvokeExpr) right).getMethod(), height - 1);
                            for (i = 0; i < result.size(); i++) {
                                if (args_mapping.containsKey(i)) {
                                    Value arg = args_mapping.get(i);
                                    states.get(arg).merge(result.get(i));
                                    //System.out.println(result.get(i).toString() + " : " + arg);
                                }
                            }
                        }
                    }
                }
                else {
                }
            }
        }
        ArrayList<State> result = new ArrayList<>();
        for (Local l: body.getParameterLocals()){
            result.add(states.get(l));
        }
        return result;
    }

    private void analyzeRefs(SootMethod call) {
        ArrayList<State> states = analyzeRefsRecursive(call, 10);
        JSONArray obj = new JSONArray();
        for (State s: states){
            obj.put(s.toJSON());
        }
        Utils.result(call, obj, "AnalyzeFunction.analyzeRefs");
    }

}
