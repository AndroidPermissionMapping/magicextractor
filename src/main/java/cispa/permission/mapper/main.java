package cispa.permission.mapper;

import java.io.*;
import java.util.ArrayList;
import java.util.Map;

import cispa.permission.mapper.magic.AnalyzeRefs;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;

import static cispa.permission.mapper.Utils.*;

public class main {

    private static final String OUTPUT = "./output/";
    private static final String DEXES_FOLDER = "./dex/";
    private static final String ANDROID_JARS = "./android-platforms/";

    private static ArrayList<SootClass> allClasses = new ArrayList<SootClass>();
    private static ArrayList<SootClass> intermediateCPClasses = new ArrayList<SootClass>();
    private static ArrayList<SootClass> intermediateCPClasses2 = new ArrayList<SootClass>();
    public static Callgraph callgraph = new Callgraph();
    public static AnalyzeMethod analyzeMethod = new AnalyzeMethod();



    public static void main(String[] args) throws IOException {
        File dir = new File(DEXES_FOLDER);
        File [] files = dir.listFiles(new FilenameFilter() {

            @Override
            public boolean accept(File dir, String name) {
                return name.endsWith("ContactsProvider.dex");
            }
        });

        File f = new File("result.json");
        f.delete();
        f.createNewFile();
        BufferedWriter myWriter = new BufferedWriter(new FileWriter(f));
        myWriter.write("[\n");
        try {
            Utils.f = myWriter;

            for (File file : files) {
                Pack p = PackManager.v().getPack("jtp");
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
        finally {
            myWriter.write("\n]");
            myWriter.flush();
            myWriter.close();

        }

    }



    private static void analyzeMethod(SootMethod m) {
        //System.out.println(m.getDeclaringClass().toString()+"."+m.getName().toString());
        //callgraph.visit(m);
        switch (m.getName()){
            case "query":
            case "insert":
            case "update":
            case "delete":
            case "refresh":
            case "call":
                new AnalyzeRefs(m, 0).run();
                break;
            case "<clinit>":
                analyzeClinit(m);
                break;
            default:
                break;
        }
    }


    private static void analyzeClinit(SootMethod call) {
        JimpleBody body = (JimpleBody) call.retrieveActiveBody();
        UnitPatchingChain units = body.getUnits();
        ArrayList<String> matches = new ArrayList<>();
        for (Unit bx : units){
            Stmt s = (Stmt) bx;
            if (s instanceof JInvokeStmt) {
                InvokeExpr invoke = ((JInvokeStmt) s).getInvokeExpr();
                if(invoke.getMethod().getName().equals("addURI") && invoke.getMethod().getDeclaringClass().getName().equals("android.content.UriMatcher")){
                    String uri;
                    try {
                        String arg0 = immediateString(invoke.getArgBox(0));
                        uri = "content://" + arg0 + "/";
                    } catch (IllegalArgumentException e){
                        uri = "content://" + "???" + "/";
                    }
                    try {
                        String arg1 = immediateString(invoke.getArgBox(1));
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
        result(call, matches, "UriMatcher", "");
    }




}