package cispa.permission.mapper.extractors

import cispa.permission.mapper.fuzzer.FuzzingGenerator
import cispa.permission.mapper.magic.State
import cispa.permission.mapper.model.InsertMagicValues

class InsertExtractor(fuzzingGenerator: FuzzingGenerator) : BaseExtractor<InsertMagicValues>(fuzzingGenerator) {
    override val methodName: String
        get() = "insert"

    override fun extract(states: List<State>): List<InsertMagicValues> {
        check(states.size == 2) { "Unsupported insert API" }

        // insert (Uri uri, ContentValues values)
        val contentValues = states[1]
        val magicContentValues = extractBundleFromState(contentValues)

        return magicContentValues.map { InsertMagicValues(it) }
    }
}