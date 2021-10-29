package no.nav.emottak.sertifikatvalidator.config

import io.netty.util.internal.StringUtil
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.util.function.Predicate
import java.util.regex.Pattern

internal class NonProxyHostsPredicate(val regex: String) : Predicate<SocketAddress?> {

    private val pattern: Pattern = Pattern.compile(regex, 2)

    override fun test(socketAddress: SocketAddress?): Boolean {
        return if (socketAddress !is InetSocketAddress) {
            false
        } else {
            val hostString = socketAddress.hostString
            hostString != null && pattern.matcher(hostString).matches()
        }
    }

    override fun toString(): String {
        return regex
    }

    companion object {
        fun fromWildcardedPattern(pattern: String): NonProxyHostsPredicate {
            val transformed: String
            if (StringUtil.isNullOrEmpty(pattern)) {
                transformed = "$^"
            } else {
                val parts = pattern.split("\\|").toTypedArray()
                for (i in parts.indices) {
                    parts[i] = transformWildcardComponent(parts[i])
                }
                transformed = parts.joinToString("|")
            }
            return NonProxyHostsPredicate(transformed)
        }

        private fun transformWildcardComponent(component: String): String {
            var wildcardComponent = component
            val parts = arrayOf("", "", "")
            if (wildcardComponent.startsWith("*")) {
                parts[0] = ".*"
                wildcardComponent = wildcardComponent.substring(1)
            }
            if (wildcardComponent.endsWith("*")) {
                parts[2] = ".*"
                wildcardComponent = wildcardComponent.substring(0, wildcardComponent.length - 1)
            }
            parts[1] = Pattern.quote(wildcardComponent)
            return parts.joinToString("")
        }
    }

}