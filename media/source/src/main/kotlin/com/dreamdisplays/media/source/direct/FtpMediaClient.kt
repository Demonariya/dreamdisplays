package com.dreamdisplays.media.source.direct

import com.dreamdisplays.api.security.model.MediaFtpUrl
import com.dreamdisplays.media.runtime.security.MediaHostGuard
import org.slf4j.LoggerFactory
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * A deliberately tiny FTP client: just enough to answer what the direct resolver asks about a pasted
 * `ftp://` link (does it exist, how big is it, can it seek, what do its first bytes look like) and to
 * read a few small ranges out of it for the duration probe. The actual playback is FFmpeg's own `ftp`
 * protocol; this exists because the HTTP probe cannot speak FTP.
 *
 * It follows FFmpeg's conventions on purpose, so "the probe worked" means "the player will open it":
 * the path is resolved against the login directory (`PWD`), anonymous login uses the same defaults,
 * and passive mode is tried as `EPSV` first, then `PASV`.
 *
 * Security notes:
 * - The data connection always goes to the host of the *control* connection. The address a server
 *   announces in a `PASV` reply is ignored, so a hostile server cannot bounce us onto another machine.
 * - Every command is built from values [MediaFtpUrl] already proved free of control characters, and
 *   [send] refuses a line break anyway.
 * - Server replies are bounded in line length and line count, and reads in size.
 */
internal object FtpMediaClient {
    private val logger = LoggerFactory.getLogger(javaClass)

    private const val DEFAULT_PORT = 21
    private const val CONNECT_TIMEOUT_MS = 8_000
    private const val READ_TIMEOUT_MS = 8_000
    private const val SNIFF_BYTES = 512
    private const val MAX_READ_BYTES = 256 * 1024
    private const val MAX_REPLY_LINES = 64
    private const val MAX_LINE_BYTES = 2_048

    /** What FFmpeg logs in with when the URL names nobody (see `ftp_connect` in libavformat). */
    private const val ANONYMOUS_USER = "anonymous"
    private const val ANONYMOUS_PASSWORD = "nopassword"

    private val EPSV_PORT = Regex("""\(\|\|\|(\d{1,5})\|\)""")
    private val PASV_PORT = Regex("""(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})""")

    /** One server reply: its three-digit code and the text of its first line. */
    private class Reply(val code: Int, val text: String)

    /**
     * Probes [url]: size, whether the server can restart a transfer at an offset (which is what makes
     * a seek possible), and the container read from the first bytes. Returns null on any failure.
     */
    fun probe(url: String): DirectMediaProbe.Result? = runCatching {
        Session.open(url).use { session ->
            val size = session.size()
            val seekable = session.supportsRestart()
            val head = session.read(0, SNIFF_BYTES)
            val contentType = DirectMediaProbe.magicContentType(head)
            DirectMediaProbe.Result(
                finalUrl = url,
                contentType = contentType,
                contentLength = size,
                acceptsRanges = seekable,
                verifiedByBytes = contentType != null,
            )
        }
    }.onFailure { logger.debug("FTP probe failed for {}: {}.", MediaFtpUrl.redact(url).take(120), it.message) }
        .getOrNull()

    /**
     * Reads ranges of one file over a single kept-open session, reconnecting once if the server drops
     * it. Close it when done. Not thread-safe; one per probe.
     */
    class RangeReader(private val url: String) : AutoCloseable {
        private var session: Session? = null

        /** Bytes `first..last` (inclusive), or null when they could not be read. */
        fun read(first: Long, last: Long): ByteArray? {
            val length = (last - first + 1).coerceIn(0, MAX_READ_BYTES.toLong()).toInt()
            if (length <= 0) return null
            repeat(2) { attempt ->
                try {
                    val s = session ?: Session.open(url).also { session = it }
                    return s.read(first, length)
                } catch (e: IOException) {
                    logger.debug("FTP range read failed (attempt {}): {}.", attempt + 1, e.message)
                    close()
                }
            }
            return null
        }

        override fun close() {
            session?.close()
            session = null
        }
    }

    /** One logged-in control connection, positioned in binary mode, bound to a single remote file. */
    private class Session private constructor(
        private val control: Socket,
        private val input: InputStream,
        private val output: OutputStream,
    ) : AutoCloseable {
        private lateinit var remotePath: String

        /** Resolves the file path and logs in. Runs once, right after the connection opens. */
        private fun handshake(ftp: MediaFtpUrl) {
            val greeting = reply()
            if (greeting.code != 220) throw IOException("Unexpected greeting ${greeting.code}.")

            val user = ftp.user?.takeIf { it.isNotEmpty() } ?: ANONYMOUS_USER
            val password = if (ftp.user == null) ANONYMOUS_PASSWORD else ftp.password
            send("USER $user")
            val login = reply()
            when (login.code) {
                230 -> Unit
                331 -> {
                    password ?: throw IOException("The server wants a password and the link has none.")
                    send("PASS $password")
                    if (reply().code != 230) throw IOException("Login refused.")
                }

                else -> throw IOException("Login refused (${login.code}).")
            }

            send("TYPE I")
            if (reply().code != 200) throw IOException("Binary mode refused.")

            send("PWD")
            val pwd = reply()
            if (pwd.code != 257) throw IOException("PWD refused (${pwd.code}).")
            remotePath = joinPath(quoted(pwd.text) ?: throw IOException("Unreadable PWD reply."), ftp.path)
        }

        /** File size from `SIZE`, or null when the server will not say. */
        fun size(): Long? {
            send("SIZE $remotePath")
            val r = reply()
            if (r.code != 213) return null
            return r.text.trim().toLongOrNull()?.takeIf { it >= 0 }
        }

        /** True when the server accepts `REST`, i.e. can resume a transfer at an offset. */
        fun supportsRestart(): Boolean {
            send("REST 0")
            return reply().code == 350
        }

        /**
         * Reads up to [length] bytes starting at [offset]. The transfer is cut short by closing the data
         * connection; the server's closing reply is consumed so the control channel stays usable.
         */
        fun read(offset: Long, length: Int): ByteArray {
            require(length in 1..MAX_READ_BYTES) { "Refusing to read $length bytes." }
            val data = openDataConnection()
            // Only a transfer that really started has a closing reply waiting on the control channel.
            var started = false
            try {
                if (offset > 0) {
                    send("REST $offset")
                    if (reply().code != 350) throw IOException("The server cannot restart at an offset.")
                }
                send("RETR $remotePath")
                val start = reply()
                if (start.code !in 100..199) throw IOException("RETR refused (${start.code}).")
                started = true

                val out = ByteArrayOutputStream(length)
                val buffer = ByteArray(minOf(length, 8 * 1024))
                val stream = data.getInputStream()
                while (out.size() < length) {
                    val n = stream.read(buffer, 0, minOf(buffer.size, length - out.size()))
                    if (n < 0) break
                    out.write(buffer, 0, n)
                }
                return out.toByteArray()
            } finally {
                runCatching { data.close() }
                if (started) {
                    // 226 when the whole file fit, 426 / 451 when we hung up first; both are expected.
                    val end = reply()
                    if (end.code >= 500) throw IOException("Transfer ended with ${end.code}.")
                }
            }
        }

        /** Opens the passive-mode data socket, trying `EPSV` then `PASV`, always towards the control host. */
        private fun openDataConnection(): Socket {
            val port = epsvPort() ?: pasvPort() ?: throw IOException("The server offers no passive mode.")
            val socket = Socket()
            try {
                socket.soTimeout = READ_TIMEOUT_MS
                // Deliberately the control connection's own address, never the one in the reply.
                socket.connect(InetSocketAddress(control.inetAddress, port), CONNECT_TIMEOUT_MS)
                return socket
            } catch (e: Throwable) {
                runCatching { socket.close() }
                throw e
            }
        }

        private fun epsvPort(): Int? {
            send("EPSV")
            val r = reply()
            if (r.code != 229) return null
            return EPSV_PORT.find(r.text)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it in 1..65535 }
        }

        private fun pasvPort(): Int? {
            send("PASV")
            val r = reply()
            if (r.code != 227) return null
            val m = PASV_PORT.find(r.text) ?: return null
            val (_, _, _, _, hi, lo) = m.destructured
            return (hi.toInt() * 256 + lo.toInt()).takeIf { it in 1..65535 }
        }

        private fun send(command: String) {
            if (command.any { it == '\r' || it == '\n' }) throw IOException("Refusing a command containing a line break.")
            output.write((command + "\r\n").toByteArray(Charsets.UTF_8))
            output.flush()
        }

        /** Reads one reply, following a multi-line one (`123-` ... `123 `) to its end. */
        private fun reply(): Reply {
            val first = line()
            if (first.length < 3 || !first.take(3).all { it in '0'..'9' }) throw IOException("Malformed reply.")
            val code = first.take(3).toInt()
            if (first.length > 3 && first[3] == '-') {
                var lines = 1
                while (true) {
                    val next = line()
                    if (++lines > MAX_REPLY_LINES) throw IOException("Reply too long.")
                    if (next.startsWith("$code ") || next == code.toString()) break
                }
            }
            return Reply(code, first.drop(4))
        }

        /** One CRLF- or LF-terminated line, bounded so a hostile server cannot feed us an endless one. */
        private fun line(): String {
            val bytes = ByteArrayOutputStream()
            while (true) {
                val b = input.read()
                if (b < 0) throw IOException("Connection closed by the server.")
                if (b == '\n'.code) break
                if (bytes.size() >= MAX_LINE_BYTES) throw IOException("Reply line too long.")
                bytes.write(b)
            }
            return bytes.toString(Charsets.UTF_8).trimEnd('\r')
        }

        override fun close() {
            runCatching { send("QUIT") }
            runCatching { control.close() }
        }

        companion object {
            /** Connects and logs in; the host guard is consulted here too, as defense in depth. */
            fun open(url: String): Session {
                val ftp = MediaFtpUrl.parse(url) ?: throw IOException("Not an ftp:// URL.")
                MediaHostGuard.requireAllowed(ftp.value)
                val uri = ftp.uri
                val host = uri.host.removeSurrounding("[", "]")
                val port = if (uri.port in 1..65535) uri.port else DEFAULT_PORT

                val socket = Socket()
                try {
                    socket.soTimeout = READ_TIMEOUT_MS
                    socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
                    val session = Session(socket, BufferedInputStream(socket.getInputStream()), socket.getOutputStream())
                    session.handshake(ftp)
                    return session
                } catch (e: Throwable) {
                    runCatching { socket.close() }
                    throw e
                }
            }

            /** The directory a `257 "/dir" is the current directory` reply names, `""` unescaped. */
            private fun quoted(text: String): String? {
                val start = text.indexOf('"')
                if (start < 0) return null
                val sb = StringBuilder()
                var i = start + 1
                while (i < text.length) {
                    val c = text[i]
                    if (c == '"') {
                        if (i + 1 < text.length && text[i + 1] == '"') {
                            sb.append('"'); i += 2; continue
                        }
                        return sb.toString()
                    }
                    sb.append(c); i++
                }
                return null
            }

            /** `av_append_path_component`: join without doubling or dropping the slash. */
            fun joinPath(base: String, path: String): String {
                if (path.isEmpty()) return base
                if (base.isEmpty()) return path
                return base.trimEnd('/') + "/" + path.trimStart('/')
            }
        }
    }
}
