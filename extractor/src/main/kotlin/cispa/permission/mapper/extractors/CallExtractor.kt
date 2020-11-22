package cispa.permission.mapper.extractors

import cispa.permission.mapper.fuzzer.FuzzingGenerator
import cispa.permission.mapper.magic.State
import cispa.permission.mapper.model.CallApiType
import cispa.permission.mapper.model.CallMethodAndArg

class CallExtractor(fuzzingGenerator: FuzzingGenerator) : BaseExtractor<CallMethodAndArg>(fuzzingGenerator) {

    override val methodName: String
        get() = "call"

    override fun extract(states: List<State>): List<CallMethodAndArg> {
        val callData: CallMethodAndArg = when (states.size) {
            // call (String method, String arg, Bundle extras)
            3 -> {
                val callApiType = CallApiType.API_11
                val methodState = states[0]
                val argState = states[1]
                val bundleState = states[2]

                extractMagicValues(callApiType, methodState, argState, bundleState)
            }

            // call (String authority, String method, String arg, Bundle extras)
            4 -> {
                val callApiType = CallApiType.API_29
                val methodState = states[1]
                val argState = states[2]
                val bundleState = states[3]

                extractMagicValues(callApiType, methodState, argState, bundleState)
            }

            else -> throw NotImplementedError("Unknown call api")
        }

        return listOf(callData)
    }

    private fun extractMagicValues(callApiType: CallApiType,
                                   methodState: State, argState: State, bundleState: State): CallMethodAndArg {
        val methodMagicValues = extractMagicStringsFromState(methodState)
        val argMagicValues = extractMagicStringsFromState(argState)
        val extraMagicValues = extractBundleFromState(bundleState)

        return CallMethodAndArg(callApiType, methodMagicValues, argMagicValues, extraMagicValues)
    }
}