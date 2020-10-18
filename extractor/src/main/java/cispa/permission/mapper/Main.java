package cispa.permission.mapper;

import cispa.permission.mapper.magic.AnalyzeRefs;
import cispa.permission.mapper.soot.AnalysisParameters;
import cispa.permission.mapper.soot.SootAnalysis;

import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        AnalysisParameters parameters = new CommandLineParser().parse(args);
        AnalyzeRefs.IGNORE_INTS = parameters.isIgnoreInts();
        new SootAnalysis(parameters).start();
    }
}