package cispa.permission.mapper.soot;

public class AnalysisParameters {
    private final String androidJarsFolderPath;
    private final String dexFolderPath;
    private final String sootOutputFolderPath;
    private final String resultsFilePath;

    private final boolean ignoreInts;

    public AnalysisParameters(
            String androidJarsFolderPath,
            String dexFolderPath,
            String sootOutputFolderPath,
            String resultsFilePath,
            boolean ignoreInts
    ) {
        this.androidJarsFolderPath = androidJarsFolderPath;
        this.dexFolderPath = dexFolderPath;
        this.sootOutputFolderPath = sootOutputFolderPath;
        this.resultsFilePath = resultsFilePath;
        this.ignoreInts = ignoreInts;
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
}
