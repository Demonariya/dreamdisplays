package com.dreamdisplays.api.security.model

import com.dreamdisplays.api.Unstable
import java.io.ByteArrayOutputStream
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.*

/**
 * A validated absolute `ftp://` media URL.
 *
 * Kept apart from [MediaHttpUrl] on purpose: every platform parser (YouTube, Twitch, Vimeo, ...) relies on
 * that type being http(s)-only, and FTP behaves differently enough that it deserves its own rules:
 *
 * - FFmpeg's `ftp` protocol does **not** percent-decode the path, while credentials *are* decoded.
 *   [toFfmpegInput] produces the form it wants, and nothing else should hand a stored URL to FFmpeg.
 * - Every decoded part (user, password, path) is checked for control characters, because they end up
 *   verbatim in `USER`, `PASS`, `SIZE` and `RETR` commands: a `%0D%0A` must never become a second command.
 * - Query strings and fragments have no meaning in an FTP URL, so they are refused instead of guessed at.
 * - Only plain `ftp` is accepted. FFmpeg has no FTPS support, so `ftps://` could never play.
 *
 * @since 1.10.x
 */
@JvmInline
@Unstable
value class MediaFtpUrl(val value: String) {
    init {
        require(parseUri(value) != null) { "Invalid FTP media URL: ${redact(value)}" }
    }

    /** Parsed URI view of [value]. */
    val uri: URI get() = URI(value)

    /** Decoded login name, or `null` when the URL carries none (anonymous login). */
    val user: String? get() = credentials().first

    /** Decoded password, or `null` when the URL carries none. */
    val password: String? get() = credentials().second

    /** Decoded path, leading slash included; relative to the login directory, as FFmpeg resolves it. */
    val path: String get() = percentDecode(uri.rawPath.orEmpty()) ?: ""

    /**
     * The URL in the shape FFmpeg's `ftp` protocol wants: path percent-decoded, credentials left encoded
     * (FFmpeg decodes those itself). Only for the very last step before FFmpeg; the Kotlin side keeps the
     * encoded form because a decoded one is not a parseable [URI] and would be refused by the host guard.
     */
    fun toFfmpegInput(): String {
        val parsed = uri
        return buildString {
            append("ftp://")
            parsed.rawUserInfo?.let { append(it).append('@') }
            append(parsed.host)
            if (parsed.port != -1) append(':').append(parsed.port)
            append(path)
        }
    }

    /** Redacted string: the password never reaches a log line through this. */
    override fun toString(): String = redact(value)

    private fun credentials(): Pair<String?, String?> {
        val raw = uri.rawUserInfo ?: return null to null
        val colon = raw.indexOf(':')
        val user = percentDecode(if (colon < 0) raw else raw.substring(0, colon))
        val password = if (colon < 0) null else percentDecode(raw.substring(colon + 1))
        return user to password
    }

    companion object {
        /** The only scheme accepted here. */
        const val SCHEME = "ftp"

        private const val PREFIX = "ftp://"

        /** Parses [input] as an absolute `ftp` URL with a host; the scheme is lower-cased in the result. */
        fun parse(input: String?, maxLength: Int = Int.MAX_VALUE): MediaFtpUrl? {
            val trimmed = input?.trim() ?: return null
            if (trimmed.isEmpty() || trimmed.length > maxLength) return null
            if (!trimmed.regionMatches(0, PREFIX, 0, PREFIX.length, ignoreCase = true)) return null
            val normalized = PREFIX + trimmed.substring(PREFIX.length)
            if (parseUri(normalized) == null) return null
            return MediaFtpUrl(normalized)
        }

        /** Returns true when [input] is accepted by [parse]. */
        fun isValid(input: String?, maxLength: Int = Int.MAX_VALUE): Boolean = parse(input, maxLength) != null

        /** True when [url] *looks* like an FTP URL (scheme only; says nothing about validity). */
        fun isFtp(url: String): Boolean = url.trimStart().regionMatches(0, PREFIX, 0, PREFIX.length, ignoreCase = true)

        /**
         * What to hand to FFmpeg for [url]: the FFmpeg form for a valid FTP URL, the input untouched for
         * anything else (http(s) URLs, `data:` playlists, ...), so callers can apply it unconditionally.
         */
        fun ffmpegInput(url: String): String = parse(url)?.toFfmpegInput() ?: url

        /** [url] with any password replaced by `***`, safe to log. Non-FTP input is returned unchanged. */
        fun redact(url: String): String {
            if (!isFtp(url)) return url
            val authorityStart = url.indexOf("://") + 3
            val authorityEnd = url.indexOf('/', authorityStart).let { if (it < 0) url.length else it }
            val at = url.lastIndexOf('@', authorityEnd - 1)
            if (at < authorityStart) return url
            val colon = url.indexOf(':', authorityStart)
            if (colon < 0 || colon > at) return url
            return url.substring(0, colon + 1) + "***" + url.substring(at)
        }

        /**
         * Decodes `%XX` escapes as UTF-8 (a `+` stays a `+`, as in FFmpeg's own decoder). Returns `null`
         * for a malformed escape or a byte sequence that is not valid UTF-8.
         */
        internal fun percentDecode(raw: String): String? {
            val out = ByteArrayOutputStream(raw.length)
            var i = 0
            while (i < raw.length) {
                val c = raw[i]
                if (c == '%') {
                    if (i + 2 >= raw.length) return null
                    val hi = Character.digit(raw[i + 1], 16)
                    val lo = Character.digit(raw[i + 2], 16)
                    if (hi < 0 || lo < 0) return null
                    out.write(hi * 16 + lo)
                    i += 3
                } else {
                    val cp = raw.codePointAt(i)
                    out.write(String(Character.toChars(cp)).toByteArray(Charsets.UTF_8))
                    i += Character.charCount(cp)
                }
            }
            return runCatching {
                Charsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(out.toByteArray()))
                    .toString()
            }.getOrNull()
        }

        /** True when [text] holds a character that would break out of a single FTP command line. */
        private fun hasControlChars(text: String): Boolean = text.any { it.code < 0x20 || it.code == 0x7F }

        private fun parseUri(value: String): URI? {
            if (value.any { it.isWhitespace() || it.isISOControl() }) return null
            val uri = runCatching { URI(value) }.getOrNull() ?: return null
            if (uri.scheme?.lowercase(Locale.ROOT) != SCHEME) return null
            if (uri.host.isNullOrBlank()) return null
            if (uri.rawQuery != null || uri.rawFragment != null) return null

            // Everything below ends up verbatim on the wire, so it has to survive decoding intact.
            val path = percentDecode(uri.rawPath.orEmpty()) ?: return null
            if (hasControlChars(path)) return null
            uri.rawUserInfo?.let { raw ->
                val colon = raw.indexOf(':')
                val user = percentDecode(if (colon < 0) raw else raw.substring(0, colon)) ?: return null
                val password = if (colon < 0) "" else percentDecode(raw.substring(colon + 1)) ?: return null
                if (hasControlChars(user) || hasControlChars(password)) return null
            }
            return uri
        }
    }
}
