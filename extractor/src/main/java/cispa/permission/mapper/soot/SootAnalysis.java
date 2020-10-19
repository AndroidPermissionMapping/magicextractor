package cispa.permission.mapper.soot;

import cispa.permission.mapper.Statistics;
import cispa.permission.mapper.Utils;
import cispa.permission.mapper.model.CallMethodAndArg;
import saarland.cispa.cp.fuzzing.serialization.FuzzingDataSerializer;
import saarland.cispa.cp.fuzzing.serialization.ResolverCallUri;
import soot.G;
import soot.Pack;
import soot.PackManager;
import soot.Transform;
import soot.options.Options;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class SootAnalysis {
    private final AnalysisParameters parameters;
    private final Statistics statistics;

    public SootAnalysis(AnalysisParameters parameters) {
        this.parameters = parameters;
        statistics = new Statistics();
    }

    private static BufferedWriter prepare(String resultsFile) throws IOException {
        File f = new File(resultsFile);
        f.delete();
        f.createNewFile();

        BufferedWriter myWriter = new BufferedWriter(new FileWriter(f));
        myWriter.write("[\n");

        Utils.f = myWriter;

        return myWriter;
    }

    private SootBodyTransformer setupSoot(String filePath) {
        G.reset();

        Options sootOptions = Options.v();
        // General
        sootOptions.set_keep_line_number(true);

        // Android related
        sootOptions.set_allow_phantom_refs(true);
        sootOptions.set_android_jars(parameters.getAndroidJarsFolderPath());
        sootOptions.set_src_prec(Options.src_prec_apk);
        sootOptions.set_process_multiple_dex(true);

        // Input
        List<String> processDirs = new ArrayList<>();
        processDirs.add(filePath);
        sootOptions.set_process_dir(processDirs);

        // Output
        sootOptions.set_output_format(Options.output_format_jimple);
        String outputFolderPath = parameters.getSootOutputFolderPath();
        if (outputFolderPath != null) {
            sootOptions.set_output_dir(outputFolderPath);
        }

        SootBodyTransformer bodyTransformer = new SootBodyTransformer(statistics);

        Pack p = PackManager.v().getPack("jtp");
        p.add(new Transform("jtp.myTransform", bodyTransformer));

        return bodyTransformer;
    }

    private List<String> findDexFiles() {
        String dexFilesDirPath = parameters.getDexFolderPath();
        File dexFilesDir = new File(dexFilesDirPath);
        return Arrays.stream(dexFilesDir.list())
                .filter(filename -> filename.endsWith(".dex"))
                .map(filename -> dexFilesDirPath + "/" + filename)
                .collect(Collectors.toList());
    }

    public void start() throws IOException {
        List<String> dexFileNames = findDexFiles();

        String resultsFile = parameters.getResultsFilePath();
        BufferedWriter myWriter = prepare(resultsFile);
        try {
            List<ResolverCallUri> results = new ArrayList<>();
            for (String filename : dexFileNames) {
                System.out.println(filename);

                SootBodyTransformer bodyTransformer = setupSoot(filename);
                soot.Main.main(new String[]{"-w"}); // need to pass String[] (bug in soot)

                // Process results
                List<ResolverCallUri> appFormatResults = convertToAppFormat(bodyTransformer);
                results.addAll(appFormatResults);
            }

            statistics.print(false);

            String appOutput = resultsFile.replace(".json", "") + ".app.json";
            FuzzingDataSerializer.INSTANCE.serialize(appOutput, results);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            myWriter.write("\n]");
            myWriter.flush();
            myWriter.close();
        }
    }

    private static List<ResolverCallUri> convertToAppFormat(SootBodyTransformer transformer) {
        final String authorityName = transformer.getAuthorityName();
        Set<CallMethodAndArg> callData = transformer.getCallMethodAndArgSet();

        List<ResolverCallUri> result = new ArrayList<>();
        for (CallMethodAndArg data : callData) {

            try {
                if (data.getMethodMagicEquals().isEmpty()) {
                    ResolverCallUri callUri = new ResolverCallUri(authorityName, null, null, null);
                    result.add(callUri);
                } else {

                    for (String methodMagicEqual : data.getMethodMagicEquals()) {
                        if (data.getArgMagicEquals().isEmpty()) {
                            ResolverCallUri callUri = new ResolverCallUri(authorityName, methodMagicEqual, null, null);
                            result.add(callUri);
                        } else {
                            for (String argMagicEqual : data.getArgMagicEquals()) {
                                ResolverCallUri callUri = new ResolverCallUri(authorityName, methodMagicEqual, argMagicEqual, null);
                                result.add(callUri);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return result;
    }
}
