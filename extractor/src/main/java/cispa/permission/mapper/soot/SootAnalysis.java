package cispa.permission.mapper.soot;

import cispa.permission.mapper.*;
import cispa.permission.mapper.fuzzer.AppFormatConverter;
import cispa.permission.mapper.fuzzer.FuzzingGenerator;
import cispa.permission.mapper.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import saarland.cispa.cp.fuzzing.serialization.*;
import soot.*;
import soot.options.Options;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
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

    private void setupSoot(String filePath, BodyTransformer bodyTransformer,
                                          ContentProviderAnalyzer providerAnalyzer) {
        G.reset();

        Options sootOptions = Options.v();
        // General
        sootOptions.set_keep_line_number(true);
        sootOptions.set_whole_program(true);

        // Android related
        sootOptions.set_allow_phantom_refs(true);
        sootOptions.set_src_prec(Options.src_prec_apk);
        sootOptions.set_android_api_version(29);

        String sootClassPath = createSootClassPath();
        sootOptions.set_soot_classpath(sootClassPath);

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

        Pack p = PackManager.v().getPack("jtp");
        p.add(new Transform("jtp.myTransform", bodyTransformer));

        PackManager.v().getPack(ContentProviderAnalyzer.PHASE_NAME).add(
                new Transform(ContentProviderAnalyzer.TRANSFORMER_NAME, providerAnalyzer)
        );
    }

    private String createSootClassPath() {
        Path pathToAndroidJar = Paths.get(parameters.getAndroidJarsFolderPath(), "/android-29/android.jar")
                .toAbsolutePath();
        Path pathToClassesJar = Paths.get(parameters.getDexFolderPath(), "classes.jar")
                .toAbsolutePath();
        return pathToAndroidJar + ":" + pathToClassesJar;
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

        Set<String> allCpClassNames = new HashSet<>();
        List<FuzzingData> results = new ArrayList<>();

        ContentProviderAnalyzer cpAnalyzer = new ContentProviderAnalyzer();
        List<CpClassResult> allCpClassResults = new ArrayList<>();

        for (String filename : dexFileNames) {
            System.out.println(filename);

            Set<String> exportedCpClasses = CpClassFinder.INSTANCE.findExportedCpClasses(filename);

            cpAnalyzer.targetClassNames = exportedCpClasses;

            if (parameters.printCpClassNames()) {
                allCpClassNames.addAll(exportedCpClasses);
            }

            SootBodyTransformer bodyTransformer = new SootBodyTransformer(filename, exportedCpClasses,
                    fuzzingGenerator, statistics);

            setupSoot(filename, bodyTransformer, cpAnalyzer);
            soot.Main.main(new String[]{"-process-multiple-dex"}); // need to pass String[] (bug in soot)

            // Process results
            List<FuzzingData> appFormatResults = convertToAppFormat(bodyTransformer);
            results.addAll(appFormatResults);

            List<CpClassResult> cpClassResults = bodyTransformer.getCpResults();
            allCpClassResults.addAll(cpClassResults);
        }

        if (parameters.printCpClassNames()) {
            allCpClassNames.forEach(System.out::println);
        }

        statistics.print(false);

        String resultsFilePath = parameters.getResultsFilePath();
        FuzzingDataSerializer.INSTANCE.serialize(resultsFilePath, results);

        cpAnalyzer.writeToFile();
        ContentProviderAnalyzer.Companion.writeToFile("oldAnalyzerResults.json", allCpClassResults);
    }

    private List<FuzzingData> convertToAppFormat(SootBodyTransformer transformer) {
        Map<String, List<FoundMagicValues>> cpClassToMagicValuesMap = transformer.getCpClassToMagicValuesMap();

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

                if (magicValues instanceof CallMethodAndArg) {
                    CallMethodAndArg data = (CallMethodAndArg) magicValues;

                    Set<String> methodMagics = data.getMethodMagicEquals();
                    Set<String> argMagics = data.getArgMagicEquals();
                    Set<BundleKey> extrasMagics = data.getExtrasMagicValues();

                    switch (data.getType()) {
                        case API_11:
                            for (String uri : providerUris) {
                                for (String method : methodMagics) {

                                    if (argMagics.isEmpty()) {
                                        handleCallExtras(fuzzingData, CallApiLevel.API_11, uri, method, null, extrasMagics);
                                        continue;
                                    }

                                    for (String arg : argMagics) {
                                        handleCallExtras(fuzzingData, CallApiLevel.API_11, uri, method, arg, extrasMagics);
                                    }
                                }
                            }

                            break;
                        case API_29:
                            final String authorityName = transformer.getAuthorityName();
                            if (authorityName == null) {
                                logger.error("Found magic values but authority name is null???");
                                continue;
                            }

                            for (String method : methodMagics) {

                                if (argMagics.isEmpty()) {
                                    handleCallExtras(fuzzingData, CallApiLevel.API_29, authorityName, method, null, extrasMagics);
                                    continue;
                                }

                                for (String arg : argMagics) {
                                    handleCallExtras(fuzzingData, CallApiLevel.API_29, authorityName, method, arg, extrasMagics);
                                }
                            }
                            break;
                        default:
                            throw new IllegalStateException("Unknown call magic values.");
                    }
                }
            }

            FuzzingData data = new FuzzingData(providerClassName, fuzzingData);
            result.add(data);
        }

        return result;
    }

    private void handleCallExtras(List<ContentProviderApi> fuzzingData, CallApiLevel apiLevel,
                                  String uri, String method, String arg, Set<BundleKey> extrasMagics) {
        if (extrasMagics.isEmpty()) {
            ResolverCallUri resolverCallUri = new ResolverCallUri(uri, apiLevel, method, arg, null);
            fuzzingData.add(resolverCallUri);
        }

        for (BundleKey extras : extrasMagics) {
            ResolverCallUri resolverCallUri = new ResolverCallUri(uri, apiLevel, method, arg, extras);
            fuzzingData.add(resolverCallUri);
        }
    }
}
