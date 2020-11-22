package cispa.permission.mapper.extractors

import cispa.permission.mapper.fuzzer.FuzzingGenerator
import cispa.permission.mapper.magic.State
import cispa.permission.mapper.model.FoundMagicValues

class MagicValueExtractor(fuzzingGenerator: FuzzingGenerator) {

    private val methodNameToExtractor: Map<String, BaseExtractor<out FoundMagicValues>>

    init {
        val extractors = listOf(
                CallExtractor(fuzzingGenerator),
                DeleteExtractor(fuzzingGenerator),
                InsertExtractor(fuzzingGenerator),
                QueryExtractor(fuzzingGenerator),
                UpdateExtractor(fuzzingGenerator)
        )

        methodNameToExtractor = mutableMapOf()
        extractors.forEach { e -> methodNameToExtractor[e.methodName] = e }
    }

    fun extract(methodName: String, states: List<State>): List<FoundMagicValues>? {
        val extractor = methodNameToExtractor[methodName]
        return extractor?.extract(states)
    }
}