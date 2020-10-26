package cispa.permission.mapper.fuzzer;

import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class FuzzingGenerator {

    private static final int RANDOM_STRING_SIZE = 5;
    private static final int ASCII_UPPERCASE_SHIFT = 65;
    private static final int ASCII_LOWERCASE_SHIFT = 97;

    private final Random random = new Random();

    public Stream<String> generateStreamForMagicSubstrings(Set<String> magicContains) {
        return magicContains
                .stream()
                .map(this::generateStringForSubstring);
    }

    public Set<String> generateUriFromMatchers(Set<String> uriMatchers) {
        return uriMatchers.stream()
                .map(matcher -> {
                    String toProcess = matcher;

                    if (matcher.contains("#")) {
                        String suffix = String.valueOf(random.nextInt(Integer.MAX_VALUE));
                        toProcess = matcher.replace("#", suffix);
                    }

                    if (matcher.contains("*")) {
                        String suffix = generateRandomString();
                        toProcess = matcher.replace("*", suffix);
                    }

                    return toProcess;
                })
                .collect(Collectors.toSet());
    }

    private String generateStringForSubstring(String string) {
        String prefix = generateRandomString();
        String suffix = generateRandomString();
        return prefix + string + suffix;
    }

    private String generateRandomString() {
        StringBuilder stringBuilder = new StringBuilder(RANDOM_STRING_SIZE);
        for (int i = 0; i < RANDOM_STRING_SIZE; i++) {
            boolean lowerCase = random.nextBoolean();
            int letter = random.nextInt(26);

            int asciiShift = lowerCase ? ASCII_LOWERCASE_SHIFT : ASCII_UPPERCASE_SHIFT;
            int charCode = asciiShift + letter;
            stringBuilder.append((char) charCode);
        }
        return stringBuilder.toString();
    }
}
