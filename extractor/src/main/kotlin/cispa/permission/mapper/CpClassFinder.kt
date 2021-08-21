package cispa.permission.mapper

import org.xmlpull.v1.XmlPullParserException
import soot.jimple.infoflow.android.axml.AXmlNode
import soot.jimple.infoflow.android.manifest.ProcessManifest
import java.io.IOException

data class ContentProviderManifestEntry(val className: String, val isExported: Boolean)

object CpClassFinder {

    private const val NAME_ATTRIBUTE_NAME = "name"
    private const val EXPORTED_ATTRIBUTE_NAME = "exported"

    fun findExportedCpClasses(apkFileName: String): Set<String> {
        val cpClassNames: MutableSet<String> = HashSet()

        // Parse AndroidManifest.xml
        try {
            val processManifest = ProcessManifest(apkFileName)
            for (provider in processManifest.providers) {
                val cpManifestEntry: ContentProviderManifestEntry = parseProviderEntry(provider)
                if (cpManifestEntry.isExported) {
                    cpClassNames.add(cpManifestEntry.className)
                }
            }

        } catch (ignored: XmlPullParserException) {
        } catch (ignored: IOException) {
        }

        return cpClassNames
    }

    private fun parseProviderEntry(node: AXmlNode): ContentProviderManifestEntry {
        val cpClassName = node.getAttribute(NAME_ATTRIBUTE_NAME).value as String
        val isExported = node.getAttribute(EXPORTED_ATTRIBUTE_NAME)?.value as Boolean?
        return ContentProviderManifestEntry(cpClassName, isExported ?: false)
    }
}