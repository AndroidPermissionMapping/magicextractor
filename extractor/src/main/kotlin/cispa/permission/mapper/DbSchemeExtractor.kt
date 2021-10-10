package cispa.permission.mapper

import soot.*

class DbSchemeExtractor : SceneTransformer() {
    companion object {
        /*
        This phase should be used for any inter-procedural/whole-program analysis.
        See: https://github.com/soot-oss/soot/wiki/Packs-and-phases-in-Soot#whole-program-packs
         */
        const val PHASE_NAME = "wjtp"
        const val TRANSFORMER_NAME = "$PHASE_NAME.DbSchemeExtractor"

        private const val SQLITE_OPEN_HELPER_CLASS_NAME = "android.database.sqlite.SQLiteOpenHelper"
    }

    lateinit var providerClassNames: Set<String>
    val providersUsingSqLiteDb = mutableSetOf<String>()

    private lateinit var currentlyProcessingProvider: SootClass
    private lateinit var currentlyProcessingClass: SootClass

    override fun internalTransform(phaseName: String?, options: MutableMap<String, String>?) {
        val scene = Scene.v()

        // SQLiteContentProvider
        for (className in providerClassNames) {
            currentlyProcessingProvider = scene.getSootClass(className)
            currentlyProcessingClass = currentlyProcessingProvider
            processFields()

            while (currentlyProcessingClass.hasSuperclass()) {
                currentlyProcessingClass = currentlyProcessingClass.superclass
                processFields()
            }
        }
    }

    private fun processFields() {
        for (field in currentlyProcessingClass.fields) {
            val type = field.type
            if (type !is RefType) {
                continue
            }

            if (isTypeSQLiteOpenHelper(type)) {
                providersUsingSqLiteDb.add(currentlyProcessingProvider.name)
                break
            }

            // Field type can inherit from SQLiteOpenHelper class
            processFieldTypeInheritance(type)
        }
    }

    private fun processFieldTypeInheritance(startType: RefType) {
        val fieldType = startType.sootClass.type
        if (isTypeSQLiteOpenHelper(fieldType)) {
            providersUsingSqLiteDb.add(currentlyProcessingProvider.name)
            return
        }

        processFieldTypeInheritanceRecursively(startType)
    }

    private fun processFieldTypeInheritanceRecursively(startType: RefType) {
        var fieldSootClass: SootClass = startType.sootClass

        while (fieldSootClass.hasSuperclass()) {
            fieldSootClass = fieldSootClass.superclass
            val fieldType = fieldSootClass.type

            if (isTypeSQLiteOpenHelper(fieldType)) {
                providersUsingSqLiteDb.add(currentlyProcessingProvider.name)
                break
            }
        }
    }

    private fun isTypeSQLiteOpenHelper(type: Type): Boolean {
        return type is RefType &&
                type.className == SQLITE_OPEN_HELPER_CLASS_NAME
    }
}