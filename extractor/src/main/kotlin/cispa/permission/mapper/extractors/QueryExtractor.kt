package cispa.permission.mapper.extractors

import cispa.permission.mapper.fuzzer.FuzzingGenerator
import cispa.permission.mapper.magic.State
import cispa.permission.mapper.model.ContentProviderQuery
import java.util.*

class QueryExtractor(fuzzingGenerator: FuzzingGenerator) : BaseExtractor<ContentProviderQuery>(fuzzingGenerator) {
    override val methodName: String
        get() = "query"

    override fun extract(states: List<State>): List<ContentProviderQuery> {
        val result = mutableListOf<ContentProviderQuery>()

        val numberOfArgs = states.size
        val argsExceptUri: MutableList<Set<String>> = ArrayList(numberOfArgs - 1)
        for (i in 1 until numberOfArgs) {
            val state = states[i]
            val magicValues: Set<String> = extractMagicStringsFromState(state)
                    .filter { item: String -> item != "null" }
                    .toSet()
            argsExceptUri.add(magicValues)
        }

        val contentProviderQuery = ContentProviderQuery(argsExceptUri)
        result.add(contentProviderQuery)
        return result
    }
}