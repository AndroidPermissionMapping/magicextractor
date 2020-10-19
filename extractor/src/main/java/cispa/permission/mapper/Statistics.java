package cispa.permission.mapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

public class Statistics {
    private static final Logger logger = LoggerFactory.getLogger(Statistics.class);

    private final ConcurrentLinkedQueue<String> contentProviderClassNames;
    private final ConcurrentLinkedQueue<String> callContentProviderNames;

    public Statistics() {
        contentProviderClassNames = new ConcurrentLinkedQueue<>();
        callContentProviderNames = new ConcurrentLinkedQueue<>();
    }

    public void reportContentProvider(String className) {
        contentProviderClassNames.add(className);
    }

    public void reportCallMethod(String fullName) {
        callContentProviderNames.add(fullName);
    }

    public void print(boolean printDetailedInformation) {
        Set<String> uniqueClassNames = findUniqueValues(contentProviderClassNames);
        logger.info("Found {} content provider.", uniqueClassNames.size());

        logger.debug("Content Provider class names:");
        uniqueClassNames.forEach(logger::debug);

        if (printDetailedInformation) {
            printCallApiStats();
        }
    }

    public void printCallApiStats() {
        logger.info("Found {} call API in content providers.", callContentProviderNames.size());
        logger.debug("Content Provider call names:");
        callContentProviderNames.forEach(logger::debug);
    }

    private Set<String> findUniqueValues(Queue<String> queue) {
        return new HashSet<>(queue);
    }
}
