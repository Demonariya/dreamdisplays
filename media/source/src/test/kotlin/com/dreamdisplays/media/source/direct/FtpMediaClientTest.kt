package com.dreamdisplays.media.source.direct

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Runs [FtpMediaClient] against a scripted in-process FTP server on loopback. */
class FtpMediaClientTest {
    init {
        // The server is on loopback, which the SSRF guard rightly refuses by default.
        System.setProperty("dreamdisplays.allowPrivateUrls", "true")
    }

    private val mp4Head = ByteArray(2048).also {
        // size, "ftyp", brand: enough for the magic sniff
        "ftypisom".toByteArray().copyInto(it, 4)
    }

    /** Minimal passive-mode FTP server serving one file at `/home/bob/movies/a.mp4`. */
    private class FakeFtp(
        val file: ByteArray,
        val allowRest: Boolean = true,
        val pasvIp: String = "127,0,0,1",
        val epsv: Boolean = true,
    ) : AutoCloseable {
        val server = ServerSocket(0, 5, InetAddress.getLoopbackAddress())
        val commands = CopyOnWriteArrayList<String>()
        private val workers = CopyOnWriteArrayList<Thread>()
        val port get() = server.localPort

        init {
            workers += thread(isDaemon = true) {
                while (!server.isClosed) {
                    val s = runCatching { server.accept() }.getOrNull() ?: break
                    workers += thread(isDaemon = true) { runCatching { serve(s) } }
                }
            }
        }

        private fun serve(c: Socket) = c.use {
            val inp = c.getInputStream().bufferedReader(Charsets.ISO_8859_1)
            val out = c.getOutputStream()
            fun say(line: String) { out.write("$line\r\n".toByteArray()); out.flush() }
            say("220 hi")
            var data: ServerSocket? = null
            var rest = 0L
            while (true) {
                val line = inp.readLine() ?: break
                commands += line
                val cmd = line.substringBefore(' ').uppercase()
                val arg = line.substringAfter(' ', "")
                when (cmd) {
                    "USER" -> say(if (arg == "anonymous" || arg == "bob") "331 pw" else "530 no")
                    "PASS" -> say("230 ok")
                    "TYPE" -> say("200 ok")
                    "PWD" -> say("257 \"/home/bob\" is current")
                    "SIZE" -> say(if (arg == "/home/bob/movies/a.mp4") "213 ${file.size}" else "550 nope")
                    "REST" -> if (allowRest) { rest = arg.toLong(); say("350 ok") } else say("502 no")
                    "EPSV" -> if (epsv) {
                        data = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
                        say("229 Entering (|||${data.localPort}|)")
                    } else say("500 no")
                    "PASV" -> {
                        data = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
                        val p = data.localPort
                        say("227 Entering ($pasvIp,${p / 256},${p % 256})")
                    }
                    "RETR" -> {
                        if (arg != "/home/bob/movies/a.mp4") { say("550 nope"); continue }
                        say("150 go")
                        val d = data!!.accept()
                        runCatching { d.getOutputStream().use { it.write(file, rest.toInt(), file.size - rest.toInt()) } }
                        data.close()
                        rest = 0L // a restart point only applies to the next transfer
                        say("226 done")
                    }
                    "QUIT" -> { say("221 bye"); break }
                    else -> say("502 ?")
                }
            }
        }

        override fun close() { server.close() }
    }

    private fun url(s: FakeFtp, path: String = "movies/a.mp4", auth: String = "bob:pw@") =
        "ftp://$auth" + "127.0.0.1:${s.port}/$path"

    @Test
    fun `probe reports size seekability and container`() {
        FakeFtp(mp4Head).use { s ->
            val r = assertNotNull(FtpMediaClient.probe(url(s)))
            assertEquals("video/mp4", r.contentType)
            assertEquals(2048L, r.contentLength)
            assertTrue(r.acceptsRanges)
            assertTrue(r.verifiedByBytes)
        }
    }

    @Test
    fun `the path is resolved against the login directory and anonymous login works`() {
        FakeFtp(mp4Head).use { s ->
            assertNotNull(FtpMediaClient.probe(url(s, auth = "")))
            assertTrue("USER anonymous" in s.commands)
            assertTrue("PASS nopassword" in s.commands)
            assertTrue("RETR /home/bob/movies/a.mp4" in s.commands)
        }
    }

    @Test
    fun `a missing file is a failed probe`() {
        FakeFtp(mp4Head).use { s ->
            assertNull(FtpMediaClient.probe(url(s, path = "movies/missing.mp4")))
        }
    }

    @Test
    fun `no restart support means not seekable`() {
        FakeFtp(mp4Head, allowRest = false).use { s ->
            val r = assertNotNull(FtpMediaClient.probe(url(s)))
            assertFalse(r.acceptsRanges)
        }
    }

    @Test
    fun `an announced pasv address is ignored and the control host is used`() {
        // The server claims the data port lives on 10.255.255.1; connecting there would hang or bounce.
        FakeFtp(mp4Head, pasvIp = "10,255,255,1", epsv = false).use { s ->
            assertNotNull(FtpMediaClient.probe(url(s)))
        }
    }

    @Test
    fun `a range reader returns the requested window`() {
        val file = ByteArray(4096) { (it % 251).toByte() }
        FakeFtp(file).use { s ->
            FtpMediaClient.RangeReader(url(s)).use { r ->
                assertContentEquals(file.copyOfRange(0, 16), r.read(0, 15))
                assertContentEquals(file.copyOfRange(1000, 1100), r.read(1000, 1099))
                assertContentEquals(file.copyOfRange(0, 8), r.read(0, 7), "The session stays usable after a cut-short transfer.")
            }
        }
    }

    @Test
    fun `a refused restart yields no bytes rather than hanging`() {
        FakeFtp(mp4Head, allowRest = false).use { s ->
            FtpMediaClient.RangeReader(url(s)).use { r -> assertNull(r.read(100, 199)) }
        }
    }
}
