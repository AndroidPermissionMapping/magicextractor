package cispa.permission.mapper.extractors

import cispa.permission.mapper.fuzzer.FuzzingGenerator
import cispa.permission.mapper.magic.BundleElement
import cispa.permission.mapper.magic.State
import cispa.permission.mapper.model.InsertMagicValues
import saarland.cispa.cp.fuzzing.serialization.ContentValue
import saarland.cispa.cp.fuzzing.serialization.ContentValueType.Companion.fromJavaClassName

class InsertExtractor(fuzzingGenerator: FuzzingGenerator) : BaseExtractor<InsertMagicValues>(fuzzingGenerator) {
    override val methodName: String
        get() = "insert"

    override fun extract(states: List<State>): List<InsertMagicValues> {
        val result = mutableListOf<InsertMagicValues>()
        for (state in states) {
            val contentValues: Set<BundleElement> = state.cv_elements

            for (bundleElement in contentValues) {
                val typeName = bundleElement.type.toString()
                val key = bundleElement.name
                val value = bundleElement.value

                check(value == null) { "Unknown value type" }

                val valueType = fromJavaClassName(typeName)
                val contentValue = ContentValue(valueType, key)

                val magicValues = InsertMagicValues(contentValue)
                result.add(magicValues)
            }
        }
        return result
    }
}