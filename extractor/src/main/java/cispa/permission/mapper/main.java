package cispa.permission.mapper;

import java.io.*;
import java.util.*;

import cispa.permission.mapper.magic.AnalyzeRefs;
import cispa.permission.mapper.model.CallMethodAndArg;
import org.apache.commons.cli.*;
import saarland.cispa.cp.fuzzing.serialization.FuzzingDataSerializer;
import saarland.cispa.cp.fuzzing.serialization.ResolverCallUri;
import soot.*;

public class main {

    private static final String OUTPUT = "./output/";
    private static final String DEXES_FOLDER = "./dex/";
    private static final String ANDROID_JARS = "./android-platforms/";

    private static String outputPath;

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

            outputPath = cmd.getOptionValue("output");

            start(outputPath, cmd.getOptionValue("soot"), cmd.getOptionValue("dexes"), cmd.getOptionValue("android"));
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("./magicextractor", options);
        }
    }

    public static void start(String outfile, String output_folder, String dexes_folder, String android_jars) throws IOException {
        File dir = new File(dexes_folder);
        File[] files = dir.listFiles((dir1, name) -> name.endsWith(".dex"));

        File f = new File(outfile);
        f.delete();
        f.createNewFile();
        BufferedWriter myWriter = new BufferedWriter(new FileWriter(f));
        myWriter.write("[\n");
        try {
            Utils.f = myWriter;

            List<ResolverCallUri> results = new ArrayList<>();

            for (File file : files) {
                System.out.println(file.getPath());

                SootBodyTransformer bodyTransformer = new SootBodyTransformer();

                Pack p = PackManager.v().getPack("jtp");
                p.add(new Transform("jtp.myTransform", bodyTransformer));

                ArrayList<String> sootOptions = new ArrayList<>(Arrays.asList("-w",
                        "-allow-phantom-refs",
                        "-android-jars", android_jars,
                        "-v",
                        "-src-prec", "apk",
                        "-f", "jimple",
                        "-process-dir", file.getPath(),
                        "-keep-line-number",
                        "-process-multiple-dex"));

                if (output_folder != null) {
                    sootOptions.add("-output-dir");
                    sootOptions.add(output_folder);
                }

                try {
                    soot.Main.main(sootOptions.toArray(new String[0]));
                    G.reset();

                    // Process results
                    List<ResolverCallUri> appFormatResults = convertToAppFormat(bodyTransformer);
                    results.addAll(appFormatResults);

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            String appOutput = outputPath.replace(".json", "") + ".app.json";
            FuzzingDataSerializer.INSTANCE.serialize(appOutput, results);

        } finally {
            myWriter.write("\n]");
            myWriter.flush();
            myWriter.close();
        }
    }

    private static List<ResolverCallUri> convertToAppFormat(SootBodyTransformer transformer) {
        Set<String> uris = transformer.getProviderUris();
        Set<CallMethodAndArg> callData = transformer.getCallMethodAndArgSet();

        List<ResolverCallUri> result = new ArrayList<>();
        for (CallMethodAndArg data : callData) {
            if (data.getMethodMagicEquals().isEmpty()) {
                for (String u : uris) {
                    ResolverCallUri callUri = new ResolverCallUri(u, null, null, null);
                    result.add(callUri);
                }
            } else {

                for (String methodMagicEqual : data.getMethodMagicEquals()) {
                    if (data.getArgMagicEquals().isEmpty()) {
                        for (String u : uris) {
                            ResolverCallUri callUri = new ResolverCallUri(u, methodMagicEqual, null, null);
                            result.add(callUri);
                        }
                    } else {

                        for (String argMagicEqual : data.getArgMagicEquals()) {
                            for (String u : uris) {
                                ResolverCallUri callUri = new ResolverCallUri(u, methodMagicEqual, argMagicEqual, null);
                                result.add(callUri);
                            }
                        }
                    }

                }
            }
        }

        return result;
    }
}