package cispa.permission.mapper;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Map;

import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.jimple.toolkits.scalar.ConstantPropagatorAndFolder;

public class main {

    private static final String OUTPUT = "./output/";
    private static final String DEXES_FOLDER = "./dex/";
    private static final String ANDROID_JARS = "./android-platforms/";

    private static ArrayList<SootClass> allClasses = new ArrayList<SootClass>();
    private static ArrayList<SootClass> intermediateCPClasses = new ArrayList<SootClass>();
    private static ArrayList<SootClass> intermediateCPClasses2 = new ArrayList<SootClass>();



    public static void main(String[] args) throws IOException {
        File dir = new File(DEXES_FOLDER);
        File [] files = dir.listFiles(new FilenameFilter() {

            @Override
            public boolean accept(File dir, String name) {
                return name.endsWith(".dex");
            }
        });

        for (File file : files) {
//            PackManager.v().getPack("wjtp").add(new Transform("wjtp.myTransform", new SceneTransformer() {
//                @Override
//                protected void internalTransform(String phaseName, Map options) {
//                    //final CallGraph cg = Scene.v().getCallGraph();
//
//                    Chain<SootClass> classes = Scene.v().getApplicationClasses();
//                    for (SootClass clazz : classes) {
//                        SootClass superclass = clazz;
//                        while (!superclass.getName().equals("android.content.ContentProvider") && superclass.hasSuperclass())
//                            superclass = superclass.getSuperclass();
//                        if (superclass.getName().equals("android.content.ContentProvider")) {
//                            analyze(clazz);
//                        }
//                    }
//                }
//            }));
            Pack p = PackManager.v().getPack("jtp");
            //p.add(new Transform("jtp.constantpropagatorandfolder", ConstantPropagatorAndFolder.v()));
            p.add(new Transform("jtp.myTransform", new BodyTransformer() {
                @Override
                protected void internalTransform(Body b, String phaseName, Map<String, String> options) {
                    SootMethod m = b.getMethod();
                    SootClass superclass = m.getDeclaringClass();
                    while (!superclass.getName().equals("android.content.ContentProvider") && superclass.hasSuperclass())
                        superclass = superclass.getSuperclass();
                    if (superclass.getName().equals("android.content.ContentProvider")) {
                        analyzeMethod(m);
                    }
                }
            }));

            System.out.println(file.getPath());

            String[] sootOptions = {
                    "-w",
                    "-allow-phantom-refs",
                    "-android-jars", ANDROID_JARS,
                    "-v",
                    "-src-prec", "apk",
                    "-f", "jimple",
                    "-process-dir", file.getPath(),
                    "-keep-line-number",
                    "-output-dir", OUTPUT,
                    "-process-multiple-dex"
            };

            try {
                soot.Main.main(sootOptions);
                G.reset();
            } catch (Exception e) {
                // Nothing
            }
        }

    }

    private static void analyzeMethod(SootMethod m) {
        //System.out.println(m.getDeclaringClass().toString()+"."+m.getName().toString());
        switch (m.getName()){
            case "call":
                analyzeCall(m);
                break;
            case "<clinit>":
                analyzeClinit(m);
                break;
            default:
                break;
        }
    }

    private static String immediate(ValueBox b){
        if (b instanceof ImmediateBox){
            Value val = b.getValue();
            if (val instanceof StringConstant)
                return ((StringConstant)val).value;
            else if (val instanceof NullConstant)
                return null;
        }
        throw new IllegalArgumentException("no immediate " + b.toString());
    }

    private static void analyzeClinit(SootMethod call) {
        JimpleBody body = (JimpleBody) call.retrieveActiveBody();
        //System.out.println(body);
        UnitPatchingChain units = body.getUnits();
        ArrayList<String> matches = new ArrayList<>();
        //System.out.println(units);
        for (Unit bx : units){
            Stmt s = (Stmt) bx;
            //System.out.println("#["+s.getClass().getName()+"]"+s.toString());
            if (s instanceof JInvokeStmt) {
                InvokeExpr invoke = ((JInvokeStmt) s).getInvokeExpr();
                if(invoke.getMethod().getName().equals("addURI") && invoke.getMethod().getDeclaringClass().getName().equals("android.content.UriMatcher")){
                    String uri;
                    try {
                        String arg0 = immediate(invoke.getArgBox(0));
                        uri = "content://" + arg0 + "/";
                    } catch (IllegalArgumentException e){
                        uri = "content://" + "???" + "/";
                    }
                    try {
                        String arg1 = immediate(invoke.getArgBox(1));
                        if (arg1 != null){
                            uri += arg1;
                        }
                    } catch (IllegalArgumentException e){
                        uri += "???";
                    }
                    matches.add(uri);
                }
            }


        }
        result(call, matches, "<clinit> UriMatcher");
    }

    private static void result(SootMethod m, ArrayList<String> matches, String mode) {
        String ma = "";
        for (String s : matches)
            ma += " \"" + s + "\",";
        System.out.println("{\"method\":\"" + m.getDeclaringClass().toString()+"."+m.getName() + "\", \"analysis\": \"" + mode + "\", \"magic\": [" + ma + "]},");
    }

    private static void analyzeCall(SootMethod call) {
        JimpleBody body = (JimpleBody) call.retrieveActiveBody();
        UnitPatchingChain units = body.getUnits();
        Local param0 = body.getParameterLocal(0);
        ArrayList<String> global_matches = new ArrayList<>();
        for (Unit bx: units){
            Stmt s = (Stmt) bx;
            if (s instanceof JAssignStmt) {
                ArrayList<String> magic_values = new ArrayList<>();
                boolean uses_param = false;
                for (ValueBox b: ((JAssignStmt)s).rightBox.getValue().getUseBoxes()){
                        if (b.getValue().equals(param0)){
                            uses_param = true;
                        }
                        try{
                            magic_values.add(immediate(b));
                        } catch (IllegalArgumentException e){

                        }
                }
                if (uses_param && !magic_values.isEmpty())
                    global_matches.addAll(magic_values);
            }

            //System.out.println(s.toString() + " - " + s.getUseBoxes().toString());

        }
        result(call, global_matches, "analyzeCall (param0 switch)");
    }

}