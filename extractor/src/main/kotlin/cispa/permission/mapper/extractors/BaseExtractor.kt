package cispa.permission.mapper.extractors

import cispa.permission.mapper.fuzzer.FuzzingGenerator
import cispa.permission.mapper.magic.State
import cispa.permission.mapper.model.FoundMagicValues
import java.util.*

abstract class BaseExtractor<T : FoundMagicValues>(private val fuzzingGenerator: FuzzingGenerator) {

    abstract val methodName: String

    abstract fun extract(states: List<State>): List<T>

    protected fun extractMagicValuesFromState(state: State): Set<String> {
        val magicValues: MutableSet<String> = HashSet(state.magic_equals)
        fuzzingGenerator
                .generateStreamForMagicSubstrings(state.magic_substring)
                .forEach { e: String -> magicValues.add(e) }
        return magicValues
    }
}