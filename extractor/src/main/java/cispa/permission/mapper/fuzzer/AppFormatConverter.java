package cispa.permission.mapper.fuzzer;

import saarland.cispa.cp.fuzzing.serialization.FuzzingData;
import saarland.cispa.cp.fuzzing.serialization.ResolverQueryApi1;

import java.util.List;
import java.util.Set;

public class AppFormatConverter {
    public static void processSelectionArgs(List<FuzzingData> result,
                                            String uri, String selection,
                                            Set<String> selectionArgs, Set<String> sortOrders) {
        if (selectionArgs.isEmpty()) {
            if (sortOrders.isEmpty()) {
                ResolverQueryApi1 resolverQueryApi1 = new ResolverQueryApi1(
                        uri,
                        null, selection, null, null);

                result.add(resolverQueryApi1);
            } else {

                for (String sortOrder : sortOrders) {
                    ResolverQueryApi1 resolverQueryApi1 = new ResolverQueryApi1(
                            uri,
                            null, selection, null, sortOrder);

                    result.add(resolverQueryApi1);
                }
            }

        } else {
            throw new IllegalStateException("Not implemented");
        }
    }
}
