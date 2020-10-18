package cispa.permission.mapper;

import cispa.permission.mapper.soot.AnalysisParameters;
import org.apache.commons.cli.*;

public class CommandLineParser {

    private static final String ARG_ANDROID = "android";
    private static final String ARG_DEXES = "dexes";
    private static final String ARG_SOOT = "soot";
    private static final String ARG_RESULTS_FILE = "output";
    private static final String ARG_IGNORE_INTS = "dont-ignore-ints";

    private Options options;
    private HelpFormatter helpFormatter;

    public CommandLineParser() {
        helpFormatter = new HelpFormatter();
        options = createOptions();
    }

    private Options createOptions() {
        Options options = new Options();

        Option opt_output = new Option("o", ARG_RESULTS_FILE, true, "output file path (required)");
        opt_output.setRequired(true);
        options.addOption(opt_output);

        Option opt_soot = new Option("s", ARG_SOOT, true, "soot output folder");
        opt_soot.setRequired(false);
        options.addOption(opt_soot);

        Option opt_dexes = new Option("d", ARG_DEXES, true, "dexes folder (required)");
        opt_dexes.setRequired(true);
        options.addOption(opt_dexes);

        Option opt_jars = new Option("a", ARG_ANDROID, true, "android jars folder (required)");
        opt_jars.setRequired(true);
        options.addOption(opt_jars);

        Option opt_ints = new Option("i", ARG_IGNORE_INTS, false, "Don't ignore ints in analysis");
        opt_ints.setRequired(false);
        options.addOption(opt_ints);

        return options;
    }

    public AnalysisParameters parse(String[] args) {
        try {
            org.apache.commons.cli.CommandLineParser parser = new DefaultParser();
            CommandLine commandLine = parser.parse(options, args);

            return new AnalysisParameters(
                    commandLine.getOptionValue(ARG_ANDROID),
                    commandLine.getOptionValue(ARG_DEXES),
                    commandLine.getOptionValue(ARG_SOOT),
                    commandLine.getOptionValue(ARG_RESULTS_FILE),
                    commandLine.getOptionValue(ARG_IGNORE_INTS) == null
            );
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            printHelp();
        }
        return null;
    }

    private void printHelp() {
        helpFormatter.printHelp("./magicextractor", options);
    }
}
