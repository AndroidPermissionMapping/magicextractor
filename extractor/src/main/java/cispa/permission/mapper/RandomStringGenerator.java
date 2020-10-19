package cispa.permission.mapper;

import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.Set;
import java.util.stream.Stream;

public class RandomStringGenerator {
    private final Random random = new Random();

    public Stream<String> generateStreamForMagicSubstrings(Set<String> magicContains) {
        return magicContains
                .stream()
                .map(this::generateStringForSubstring);
    }

    private String generateStringForSubstring(String string) {
        String prefix = generateRandomString(5);
        String suffix = generateRandomString(5);
        return prefix + string + suffix;
    }

    private String generateRandomString(int size) {
        byte[] array = new byte[size];
        random.nextBytes(array);
        return new String(array, StandardCharsets.US_ASCII);
    }
}
