package cispa.permission.mapper.soot;

import cispa.permission.mapper.Statistics;
import cispa.permission.mapper.extractors.MagicValueExtractor;
import cispa.permission.mapper.fuzzer.FuzzingGenerator;
import cispa.permission.mapper.magic.AnalyzeRefs;
import cispa.permission.mapper.model.FoundMagicValues;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.JimpleBody;
import soot.jimple.Stmt;
import soot.jimple.internal.JInvokeStmt;

import java.util.*;

import static cispa.permission.mapper.Utils.immediateString;

public class SootBodyTransformer extends BodyTransformer {

    private final FuzzingGenerator fuzzingGenerator;

    private final String dexFileName;
    private final Statistics statistics;

    private final Set<String> providerUriMatchers;
    private final Map<String, List<FoundMagicValues>> cpClassToMagicValuesMap;

    private String authorityName;

    public SootBodyTransformer(String dexFileName, FuzzingGenerator fuzzingGenerator, Statistics statistics) {
        this.dexFileName = dexFileName;
        this.fuzzingGenerator = fuzzingGenerator;
        this.statistics = statistics;

        providerUriMatchers = new HashSet<>();
        cpClassToMagicValuesMap = new HashMap<>();
    }

    @Override
    protected void internalTransform(Body b, String phaseName, Map<String, String> options) {
        SootMethod m = b.getMethod();
        SootClass superclass = m.getDeclaringClass();
        while (!superclass.getName().equals("android.content.ContentProvider") && superclass.hasSuperclass())
            superclass = superclass.getSuperclass();

        if (superclass.getName().equals("android.content.ContentProvider")) {
            String contentProviderClassName = m.getDeclaringClass().toString();
            statistics.reportContentProvider(dexFileName + ": " + contentProviderClassName);

            analyzeMethod(m);
        }
    }

    private void analyzeMethod(SootMethod m) {
        //System.out.println(m.getDeclaringClass().toString()+"."+m.getName().toString());
        //callgraph.visit(m);
        switch (m.getName()) {
            case "query":
            case "insert":
            case "update":
            case "delete":
            case "refresh":
            case "call":
                MagicValueExtractor magicValueExtractor = new MagicValueExtractor(fuzzingGenerator);
                AnalyzeRefs analyzeRefs = new AnalyzeRefs(magicValueExtractor, statistics, m, 0);
                analyzeRefs.run();

                Map<String, List<FoundMagicValues>> magicValues = analyzeRefs.getCpClassNameToMagicValuesMap();

                magicValues.forEach((cpClassName, magics) -> {
                    List<FoundMagicValues> existingMagicValues = cpClassToMagicValuesMap
                            .getOrDefault(cpClassName, new ArrayList<>());
                    existingMagicValues.addAll(magics);

                    cpClassToMagicValuesMap.put(cpClassName, existingMagicValues);
                });

                break;
            case "<clinit>":
                analyzeClinit(m);
            default:
                break;
        }
    }

    private void analyzeClinit(SootMethod call) {
        JimpleBody body = (JimpleBody) call.retrieveActiveBody();
        UnitPatchingChain units = body.getUnits();
        ArrayList<String> matches = new ArrayList<>();
        for (Unit bx : units) {
            Stmt s = (Stmt) bx;
            if (s instanceof JInvokeStmt) {
                InvokeExpr invoke = s.getInvokeExpr();
                if (invoke.getMethod().getName().equals("addURI") && invoke.getMethod().getDeclaringClass().getName().equals("android.content.UriMatcher")) {
                    String uri;
                    try {
                        String arg0 = immediateString(invoke.getArgBox(0));
                        uri = "content://" + arg0 + "/";

                        if (authorityName == null) {
                            authorityName = uri;
                        }
                    } catch (IllegalArgumentException e) {
                        uri = "content://" + "???" + "/";
                    }
                    try {
                        String arg1 = immediateString(invoke.getArgBox(1));
                        if (arg1 != null) {
                            uri += arg1;
                        }
                    } catch (IllegalArgumentException e) {
                        uri += "???";
                    }
                    matches.add(uri);
                }
            }


        }
        providerUriMatchers.addAll(matches);
    }

    public Set<String> getProviderUriMatchers() {
        return providerUriMatchers;
    }

    public String getAuthorityName() {
        return authorityName;
    }

    public Map<String, List<FoundMagicValues>> getCpClassToMagicValuesMap() {
        return cpClassToMagicValuesMap;
    }

    public String getDexFileName() {
        return dexFileName;
    }

}
