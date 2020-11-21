package cispa.permission.mapper.extractors

import cispa.permission.mapper.fuzzer.FuzzingGenerator
import cispa.permission.mapper.magic.State
import cispa.permission.mapper.model.CallMethodAndArg

class CallExtractor(fuzzingGenerator: FuzzingGenerator) : BaseExtractor<CallMethodAndArg>(fuzzingGenerator) {

    override val methodName: String
        get() = "call"

    override fun extract(states: List<State>): List<CallMethodAndArg> {
        val result = mutableListOf<CallMethodAndArg>()

        val numberOfArgs = states.size
        val firstArg = states[0]
        val secondArg = states[1]

        when (numberOfArgs) {
            3 -> { // ContentProvider.call(..) with uri
                val methodMagicValues = extractMagicValuesFromState(firstArg)
                val argMagicValues = extractMagicValuesFromState(secondArg)
                val callData = CallMethodAndArg(methodMagicValues, argMagicValues)

                result.add(callData)

            }
            4 -> { // ContentProvider.call(..) with authority - API 29+
                // Process 1st arg - authority (String)
                check(firstArg.magic_equals.isEmpty()) { "Not implemented - call API 29+" }
            }
            else -> {
                throw IllegalStateException("Not implemented")
            }
        }
        return result
    }
}