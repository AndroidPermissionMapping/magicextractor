package cispa.permission.mapper

import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import soot.Scene
import soot.SceneTransformer
import soot.Transformer
import soot.jimple.IntConstant
import soot.jimple.StringConstant
import soot.jimple.internal.JInvokeStmt
import soot.jimple.internal.JVirtualInvokeExpr
import java.io.File

@Serializable
data class UriMatcherCall(val authority: String, val path: String, val code: Int)

@Serializable
data class CpClassResult(val className: String, val uris: List<UriMatcherCall>)

class UriMatcherAnalyzer : SceneTransformer(), ContentProviderAnalyzer {
    companion object {
        /*
        This phase should be used for any inter-procedural/whole-program analysis.
        See: https://github.com/soot-oss/soot/wiki/Packs-and-phases-in-Soot#whole-program-packs
         */
        const val PHASE_NAME = "wjtp"
        const val TRANSFORMER_NAME = "$PHASE_NAME.ContentProviderAnalyzer"

        public fun writeToFile(fileName: String, cpResults: List<CpClassResult>) {
            val format = Json { prettyPrint = true }
            val jsonString = format.encodeToString(ListSerializer(CpClassResult.serializer()), cpResults)
            File(fileName).writeText(jsonString)
        }
    }

    override val phaseName: String
        get() = PHASE_NAME

    override val transformerName: String
        get() = TRANSFORMER_NAME

    override val transformer: Transformer
        get() = this

    public lateinit var targetClassNames: Set<String>
    private val cpResults = mutableListOf<CpClassResult>()

    override fun internalTransform(phaseName: String?, options: MutableMap<String, String>?) {
        val scene = Scene.v()

        for (cpClassName in targetClassNames) {
            val sootClass = scene.getSootClass(cpClassName)
            val uriMatcherCalls = mutableListOf<UriMatcherCall>()

            try {
                val clinitMethod = sootClass.getMethodByName("<clinit>")

                val body = clinitMethod.retrieveActiveBody()
                for (unit in body.units) {

                    try {
                        if (unit is JInvokeStmt) {
                            val value = unit.invokeExprBox.value
                            if (value is JVirtualInvokeExpr) {
                                if (value.methodRef.declaringClass.name == "android.content.UriMatcher") {
                                    if (value.methodRef.name == "addURI") {
                                        val u = UriMatcherCall(
                                            (value.args[0] as StringConstant).value,
                                            (value.args[1] as StringConstant).value,
                                            (value.args[2] as IntConstant).value
                                        )
                                        uriMatcherCalls.add(u)
                                    }
                                }
                            }
                        }
                    } catch (e: RuntimeException) {
                        // Argument is null
                    }
                }

            } catch (e: RuntimeException) {
                // Method does not exist
            }



            if (uriMatcherCalls.isNotEmpty()) {
                cpResults.add(CpClassResult(cpClassName, uriMatcherCalls))
            }
        }
    }

    public fun writeToFile() {
        writeToFile("newAnalyzerResults.json", cpResults)
    }
}