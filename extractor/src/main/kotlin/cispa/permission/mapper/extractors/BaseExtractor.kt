package cispa.permission.mapper.extractors

import cispa.permission.mapper.fuzzer.FuzzingGenerator
import cispa.permission.mapper.magic.BundleElement
import cispa.permission.mapper.magic.State
import cispa.permission.mapper.model.FoundMagicValues
import saarland.cispa.cp.fuzzing.serialization.BundleKey
import saarland.cispa.cp.fuzzing.serialization.JavaType
import java.util.*

abstract class BaseExtractor<T : FoundMagicValues>(private val fuzzingGenerator: FuzzingGenerator) {

    abstract val methodName: String

    abstract fun extract(states: List<State>): List<T>

    protected fun extractMagicStringsFromState(state: State): Set<String> {
        val magicValues: MutableSet<String> = HashSet(state.magic_equals)
        fuzzingGenerator
                .generateStreamForMagicSubstrings(state.magic_substring)
                .forEach { e: String -> magicValues.add(e) }
        return magicValues
    }

    protected fun extractBundleFromState(state: State): Set<BundleKey> {
        val result = mutableSetOf<BundleKey>()
        val contentValues: Set<BundleElement> = state.cv_elements

        for (bundleElement in contentValues) {
            val typeName = bundleElement.type.toString()
            val key = bundleElement.name
            val value = bundleElement.value

            check(value == null) { "Unknown value type" }

            val valueType = JavaType.fromClassName(typeName)
            val contentValue = BundleKey(valueType, key)

            result.add(contentValue)
        }
        return result
    }
}