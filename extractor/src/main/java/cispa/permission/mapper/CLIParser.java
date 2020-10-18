package cispa.permission.mapper;

import org.apache.commons.cli.*;
import soot.jimple.parser.Parse;

public class CLIParser {

    private Options options;
    private HelpFormatter helpFormatter;

    public CLIParser() {
        helpFormatter = new HelpFormatter();
        options = createOptions();
    }

    private Options createOptions() {
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

        return options;
    }

    public CommandLine parse(String[] args) {
        try {
            CommandLineParser parser = new DefaultParser();
            return parser.parse(options, args);
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
