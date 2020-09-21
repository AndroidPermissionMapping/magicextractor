package cispa.permission.mapper;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import cispa.permission.mapper.magic.AnalyzeRefs;
import org.apache.commons.cli.*;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;

import static cispa.permission.mapper.Utils.*;

public class main {

    private static final String OUTPUT = "./output/";
    private static final String DEXES_FOLDER = "./dex/";
    private static final String ANDROID_JARS = "./android-platforms/";



    public static void main(String[] args) throws IOException {
        Options options = new Options();

        Option opt_output = new Option("o", "output", true, "output file path (required)");
        opt_output.setRequired(true);
        options.addOption(opt_output);

        Option opt_soot = new Option("s", "soot", true, "soot output folder");
        opt_soot.setRequired(false);
        options.addOption(opt_soot);

        Option opt_dexes = new Option("d", "dexes", true, "dexes folder (required)");
        opt_dexes.setRequired(true);
        options.addOption(opt_dexes);


        Option opt_jars = new Option("a", "android", true, "android jars folder (required)");
        opt_jars.setRequired(true);
        options.addOption(opt_jars);

        Option opt_ints = new Option("i", "dont-ignore-ints", false, "Don't ignore ints in analysis");
        opt_ints.setRequired(false);
        options.addOption(opt_ints);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
            AnalyzeRefs.IGNORE_INTS = cmd.getOptionValue("dont-ignore-ints") == null;
            start(cmd.getOptionValue("output"), cmd.getOptionValue("soot"), cmd.getOptionValue("dexes"), cmd.getOptionValue("android"));
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("./magicextractor", options);
        }
    }

    public static void start(String outfile, String output_folder, String dexes_folder, String android_jars) throws IOException {
        File dir = new File(dexes_folder);
        File [] files = dir.listFiles((dir1, name) -> name.endsWith(".dex"));

        File f = new File(outfile);
        f.delete();
        f.createNewFile();
        BufferedWriter myWriter = new BufferedWriter(new FileWriter(f));
        myWriter.write("[\n");
        try {
            Utils.f = myWriter;

            for (File file : files) {
                System.out.println(file.getPath());
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

                ArrayList<String> sootOptions = new ArrayList<>(Arrays.asList("-w",
                        "-allow-phantom-refs",
                        "-android-jars", android_jars,
                        "-v",
                        "-src-prec", "apk",
                        "-f", "jimple",
                        "-process-dir", file.getPath(),
                        "-keep-line-number",
                        "-process-multiple-dex"));

                if (output_folder != null){
                    sootOptions.add("-output-dir");
                    sootOptions.add(output_folder);
                }

                try {
                    soot.Main.main(sootOptions.toArray(new String[0]));
                    G.reset();
                } catch (Exception e) {
                    e.printStackTrace();
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
                InvokeExpr invoke = s.getInvokeExpr();
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