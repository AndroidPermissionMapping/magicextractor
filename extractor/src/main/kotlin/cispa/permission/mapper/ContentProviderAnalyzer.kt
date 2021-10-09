package cispa.permission.mapper

import soot.Transformer

interface ContentProviderAnalyzer {
    val phaseName: String
    val transformerName: String
    val transformer: Transformer
}