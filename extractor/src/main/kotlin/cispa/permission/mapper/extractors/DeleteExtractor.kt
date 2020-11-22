package cispa.permission.mapper.extractors

import cispa.permission.mapper.fuzzer.FuzzingGenerator
import cispa.permission.mapper.magic.State
import cispa.permission.mapper.model.DeleteMagicValues

class DeleteExtractor(fuzzingGenerator: FuzzingGenerator) : BaseExtractor<DeleteMagicValues>(fuzzingGenerator) {
    override val methodName: String
        get() = "delete"

    override fun extract(states: List<State>): List<DeleteMagicValues> {
        check(states.size == 3) { "Unsupported insert API" }

        // delete (Uri uri, String selection, String[] selectionArgs)
        val selectionState = states[1]
        val selectionMagicValues = extractMagicStringsFromState(selectionState)

        return listOf(DeleteMagicValues(selectionMagicValues))
    }
}