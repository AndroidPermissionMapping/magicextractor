package cispa.permission.mapper

import soot.Body
import soot.BodyTransformer
import soot.SootClass
import soot.SootMethod

data class PhantomClass(val className: String, val usedInClass: String)

class PhantomClassFinder : BodyTransformer(), ContentProviderAnalyzer {
    companion object {
        /*
        This is usually where you want to place your intra-procedural analyses.
        See: https://github.com/soot-oss/soot/wiki/Packs-and-phases-in-Soot#jimple-packs-jtp-jop-jap
         */
        const val PHASE_NAME = "jtp"
        const val TRANSFORMER_NAME = "$PHASE_NAME.PhantomClassFinder"
    }

    override val phaseName: String
        get() = PHASE_NAME

    override val transformerName: String
        get() = TRANSFORMER_NAME

    override val transformer: BodyTransformer
        get() = this

    public val targetClassNames = mutableSetOf<String>()

    private val phantomClassNames = mutableSetOf<PhantomClass>()

    override fun internalTransform(body: Body?, phase: String?, options: MutableMap<String, String>?) {
        if (!needToProcessBody(body!!)) {
            return
        }

        val method: SootMethod = body.method
        val providerSootClass = method.declaringClass

        val isPhantom = providerSootClass.isPhantomClass
        if (isPhantom) {
            val phantom = PhantomClass(providerSootClass.name, providerSootClass.name)
            phantomClassNames.add(phantom)
        }

        findPhantomClassesRecursively(providerSootClass, providerSootClass)
    }

    private fun needToProcessBody(body: Body): Boolean {
        val classNameOfBody = body.method.declaringClass.name
        return targetClassNames.stream()
            .anyMatch { suffix: String? -> classNameOfBody.endsWith(suffix!!) }
    }

    fun printAllPhantomClassNames() {
        if (phantomClassNames.isEmpty()) return

        println("Phantom Classes:")
        for (phantom in phantomClassNames) {
            println("${phantom.usedInClass}: ${phantom.className}")
        }
    }

    private fun findPhantomClassesRecursively(startSootClass: SootClass, providerSootClass: SootClass) {
        var sootClass: SootClass = startSootClass
        var isPhantom: Boolean

        while (sootClass.hasSuperclass()) {
            sootClass = sootClass.superclass
            isPhantom = sootClass.isPhantomClass
            if (isPhantom) {
                val phantom = PhantomClass(sootClass.name, providerSootClass.name)
                phantomClassNames.add(phantom)
            }
        }
    }
}