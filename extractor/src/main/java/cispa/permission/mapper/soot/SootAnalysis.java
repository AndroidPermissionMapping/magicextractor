package cispa.permission.mapper.soot;

import cispa.permission.mapper.Statistics;
import cispa.permission.mapper.fuzzer.AppFormatConverter;
import cispa.permission.mapper.fuzzer.FuzzingGenerator;
import cispa.permission.mapper.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saarland.cispa.cp.fuzzing.serialization.*;
import soot.G;
import soot.Pack;
import soot.PackManager;
import soot.Transform;
import soot.options.Options;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class SootAnalysis {
    private static final Logger logger = LoggerFactory.getLogger(SootAnalysis.class);

    private final AnalysisParameters parameters;
    private final FuzzingGenerator fuzzingGenerator;
    private final Statistics statistics;

    public SootAnalysis(AnalysisParameters parameters) {
        this.parameters = parameters;
        fuzzingGenerator = new FuzzingGenerator();
        statistics = new Statistics();
    }

    private static BufferedWriter prepare(String resultsFile) throws IOException {
        File f = new File(resultsFile);
        f.delete();
        f.createNewFile();

        BufferedWriter myWriter = new BufferedWriter(new FileWriter(f));
        myWriter.write("[\n");


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

        SootBodyTransformer bodyTransformer = new SootBodyTransformer(filePath, fuzzingGenerator, statistics);

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

    public void start() {
        List<String> dexFileNames = findDexFiles();

        List<FuzzingData> results = new ArrayList<>();
        for (String filename : dexFileNames) {
            System.out.println(filename);

            SootBodyTransformer bodyTransformer = setupSoot(filename);
            soot.Main.main(new String[]{"-process-multiple-dex"}); // need to pass String[] (bug in soot)

            // Process results
            List<FuzzingData> appFormatResults = convertToAppFormat(bodyTransformer);
            results.addAll(appFormatResults);
        }

        statistics.print(false);

        String resultsFilePath = parameters.getResultsFilePath();
        FuzzingDataSerializer.INSTANCE.serialize(resultsFilePath, results);
    }

    private List<FuzzingData> convertToAppFormat(SootBodyTransformer transformer) {
        final String authorityName = transformer.getAuthorityName();
        Map<String, List<FoundMagicValues>> cpClassToMagicValuesMap = transformer.getCpClassToMagicValuesMap();

        if (authorityName == null && !cpClassToMagicValuesMap.isEmpty()) {
            String dexFileName = transformer.getDexFileName();
            logger.error(dexFileName + ": Magic values found but no authority name! " +
                    "Magic values: " + cpClassToMagicValuesMap.toString());
            return Collections.emptyList();
        }

        final Set<String> providerUriMatchers = transformer.getProviderUriMatchers();
        final Set<String> providerUris = fuzzingGenerator.generateUriFromMatchers(providerUriMatchers);

        List<FuzzingData> result = new ArrayList<>();

        for (Map.Entry<String, List<FoundMagicValues>> entry : cpClassToMagicValuesMap.entrySet()) {
            final String providerClassName = entry.getKey();
            final List<FoundMagicValues> foundMagicValues = entry.getValue();

            final List<ContentProviderApi> fuzzingData = new ArrayList<>();

            for (FoundMagicValues magicValues : foundMagicValues) {
                if (magicValues instanceof ContentProviderQuery) {
                    ContentProviderQuery data = (ContentProviderQuery) magicValues;
                    List<Set<String>> args = data.getArgs();

                    if (data.isApi1Implementation()) {
                        for (String uri : providerUris) {
                            Set<String> projections = args.get(0);

                            if (projections.isEmpty()) {
                                Set<String> selections = args.get(1);
                                Set<String> selectionArgs = args.get(2);
                                Set<String> sortOrders = args.get(3);

                                if (selections.isEmpty()) {
                                    AppFormatConverter
                                            .processSelectionArgs(fuzzingData,
                                                    uri, null, selectionArgs, sortOrders);

                                } else {
                                    selections.forEach(selection -> AppFormatConverter
                                            .processSelectionArgs(fuzzingData,
                                                    uri, selection, selectionArgs, sortOrders));
                                }
                            } else {
                                throw new IllegalStateException("Not implemented");
                            }
                        }
                    }

                }

                if (magicValues instanceof UpdateMagicValues) {
                    UpdateMagicValues data = (UpdateMagicValues) magicValues;

                    Set<BundleKey> contentValues = data.getContentValues();
                    Set<String> selectionStrings = data.getSelections();

                    for (String uri : providerUris) {
                        for (BundleKey contentValue : contentValues) {
                            for (String selectionString : selectionStrings) {
                                ResolverCallUpdate resolverCallUpdate =
                                        new ResolverCallUpdate(uri, contentValue, selectionString);
                                fuzzingData.add(resolverCallUpdate);
                            }
                        }
                    }
                }

                if (magicValues instanceof DeleteMagicValues) {
                    DeleteMagicValues data = (DeleteMagicValues) magicValues;
                    Set<String> selectionStrings = data.getSelectionStrings();

                    for (String uri : providerUris) {
                        for (String selection : selectionStrings) {
                            ResolverCallDelete resolverCallDelete = new ResolverCallDelete(uri, selection);
                            fuzzingData.add(resolverCallDelete);
                        }
                    }
                }

                if (magicValues instanceof InsertMagicValues) {
                    InsertMagicValues data = (InsertMagicValues) magicValues;

                    for (String uri : providerUris) {
                        ResolverCallInsert resolverCallInsert = new ResolverCallInsert(uri, data.getContentValue());
                        fuzzingData.add(resolverCallInsert);
                    }
                }

                /* if (magicValues instanceof CallMethodAndArg) {
                    CallMethodAndArg data = (CallMethodAndArg) magicValues;
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
                } */
            }

            FuzzingData data = new FuzzingData(providerClassName, fuzzingData);
            result.add(data);
        }

        return result;
    }
}
