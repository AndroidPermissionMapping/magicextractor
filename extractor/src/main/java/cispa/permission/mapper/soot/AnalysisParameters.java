package cispa.permission.mapper.soot;

public class AnalysisParameters {
    private final String androidJarsFolderPath;
    private final String dexFolderPath;
    private final String sootOutputFolderPath;
    private final String resultsFilePath;

    private final boolean ignoreInts;
    private final boolean printCpClassNames;
    private final boolean findPhantomRefs;

    public AnalysisParameters(
            String androidJarsFolderPath,
            String dexFolderPath,
            String sootOutputFolderPath,
            String resultsFilePath,
            boolean ignoreInts,
            boolean printCpClassNames,
            boolean findPhantomRefs
    ) {
        this.androidJarsFolderPath = androidJarsFolderPath;
        this.dexFolderPath = dexFolderPath;
        this.sootOutputFolderPath = sootOutputFolderPath;
        this.resultsFilePath = resultsFilePath;
        this.ignoreInts = ignoreInts;
        this.printCpClassNames = printCpClassNames;
        this.findPhantomRefs = findPhantomRefs;
    }

    public String getAndroidJarsFolderPath() {
        return androidJarsFolderPath;
    }

    public String getDexFolderPath() {
        return dexFolderPath;
    }

    public String getSootOutputFolderPath() {
        return sootOutputFolderPath;
    }

    public String getResultsFilePath() {
        return resultsFilePath;
    }

    public boolean isIgnoreInts() {
        return ignoreInts;
    }

    public boolean printCpClassNames() {
        return printCpClassNames;
    }

    public boolean findPhantomRefs() {
        return findPhantomRefs;
    }
}
