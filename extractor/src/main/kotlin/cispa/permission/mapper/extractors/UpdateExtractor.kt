package cispa.permission.mapper.extractors

import cispa.permission.mapper.fuzzer.FuzzingGenerator
import cispa.permission.mapper.magic.State
import cispa.permission.mapper.model.UpdateMagicValues

class UpdateExtractor(fuzzingGenerator: FuzzingGenerator) : BaseExtractor<UpdateMagicValues>(fuzzingGenerator) {
    override val methodName: String
        get() = "update"

    override fun extract(states: List<State>): List<UpdateMagicValues> {
        check(states.size == 4) { "Unknown update API" }

        // update (Uri uri, ContentValues values, String selection, String[] selectionArgs) - API 1+
        val contentValueState = states[1]
        val magicContentValues = extractBundleFromState(contentValueState)

        val selectionState = states[2]
        val magicSelections = extractMagicStringsFromState(selectionState)

        return listOf(UpdateMagicValues(magicContentValues, magicSelections))
    }
}