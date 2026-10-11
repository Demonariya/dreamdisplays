package com.dreamdisplays.api.security.model

import com.dreamdisplays.api.media.source.url.CustomMediaUrls
import com.dreamdisplays.api.security.policy.MediaUrlPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MediaFtpUrlTest {
    @Test
    fun `a plain ftp url is accepted and its scheme is normalized`() {
        assertEquals("ftp://files.example.com/movies/a.mp4", MediaFtpUrl.parse("ftp://files.example.com/movies/a.mp4")?.value)
        assertEquals("ftp://files.example.com/a.mp4", MediaFtpUrl.parse("  FTP://files.example.com/a.mp4 ")?.value)
        assertEquals("ftp://host:2121/a.mp4", MediaFtpUrl.parse("ftp://host:2121/a.mp4")?.value)
    }

    @Test
    fun `only plain ftp is accepted`() {
        assertNull(MediaFtpUrl.parse("ftps://example.com/a.mp4"), "FFmpeg has no FTPS, so it could never play.")
        assertNull(MediaFtpUrl.parse("sftp://example.com/a.mp4"))
        assertNull(MediaFtpUrl.parse("https://example.com/a.mp4"))
        assertNull(MediaFtpUrl.parse("file:///etc/passwd"))
        assertNull(MediaFtpUrl.parse("example.com/a.mp4"))
        assertNull(MediaFtpUrl.parse("ftp://"))
        assertNull(MediaFtpUrl.parse("ftp:///a.mp4"))
        assertNull(MediaFtpUrl.parse(null))
        assertNull(MediaFtpUrl.parse(""))
    }

    @Test
    fun `queries and fragments have no meaning in an ftp url and are refused`() {
        assertNull(MediaFtpUrl.parse("ftp://host/a.mp4?x=1"))
        assertNull(MediaFtpUrl.parse("ftp://host/a.mp4#t=10"))
    }

    @Test
    fun `an encoded line break can never become a second ftp command`() {
        assertNull(MediaFtpUrl.parse("ftp://host/a.mp4%0D%0ADELE%20x"), "Path.")
        assertNull(MediaFtpUrl.parse("ftp://host/a%0Ab.mp4"), "A bare LF is enough to inject.")
        assertNull(MediaFtpUrl.parse("ftp://us%0D%0Aer:pw@host/a.mp4"), "User name.")
        assertNull(MediaFtpUrl.parse("ftp://user:p%0D%0Aw@host/a.mp4"), "Password.")
        assertNull(MediaFtpUrl.parse("ftp://host/a%00.mp4"), "NUL.")
        assertNull(MediaFtpUrl.parse("ftp://host/a%7F.mp4"), "DEL.")
        assertNull(MediaFtpUrl.parse("ftp://host/a b.mp4"), "A literal space is not a valid URL.")
    }

    @Test
    fun `malformed escapes are refused`() {
        assertNull(MediaFtpUrl.parse("ftp://host/a%2.mp4"))
        assertNull(MediaFtpUrl.parse("ftp://host/a%.mp4"))
        assertNull(MediaFtpUrl.parse("ftp://host/a%ZZ.mp4"))
        assertNull(MediaFtpUrl.parse("ftp://host/a%E9.mp4"), "A lone Latin-1 byte is not valid UTF-8.")
    }

    @Test
    fun `path and credentials are decoded the way the player will use them`() {
        val url = MediaFtpUrl.parse("ftp://bob:s%3Acr%40t@host/My%20Movies/%E2%9C%93.mp4")!!
        assertEquals("bob", url.user)
        assertEquals("s:cr@t", url.password, "A colon or at-sign in a password is percent-encoded in the URL.")
        assertEquals("/My Movies/✓.mp4", url.path)
    }

    @Test
    fun `an anonymous url has no credentials`() {
        val url = MediaFtpUrl.parse("ftp://host/a.mp4")!!
        assertNull(url.user)
        assertNull(url.password)
    }

    @Test
    fun `ffmpeg gets a decoded path but still-encoded credentials`() {
        // FFmpeg's ftp protocol decodes the credentials itself and never decodes the path.
        val url = MediaFtpUrl.parse("ftp://bob:s%3Acr%40t@host:2121/My%20Movies/a%2Bb.mp4")!!
        assertEquals("ftp://bob:s%3Acr%40t@host:2121/My Movies/a+b.mp4", url.toFfmpegInput())
        assertEquals("ftp://host/a.mp4", MediaFtpUrl.parse("ftp://host/a.mp4")!!.toFfmpegInput())
    }

    @Test
    fun `ffmpegInput leaves anything that is not an ftp url alone`() {
        assertEquals("https://example.com/a%20b.mp4", MediaFtpUrl.ffmpegInput("https://example.com/a%20b.mp4"))
        assertEquals("data:application/vnd.apple.mpegurl;base64,QUJD", MediaFtpUrl.ffmpegInput("data:application/vnd.apple.mpegurl;base64,QUJD"))
        assertEquals("ftp://host/a b.mp4", MediaFtpUrl.ffmpegInput("ftp://host/a%20b.mp4"))
        assertEquals("ftp://host/a%0D%0Ab.mp4", MediaFtpUrl.ffmpegInput("ftp://host/a%0D%0Ab.mp4"), "An invalid one is not rewritten.")
    }

    @Test
    fun `passwords never reach a log line`() {
        assertEquals("ftp://bob:***@host/a.mp4", MediaFtpUrl.redact("ftp://bob:hunter2@host/a.mp4"))
        assertEquals("ftp://bob@host/a.mp4", MediaFtpUrl.redact("ftp://bob@host/a.mp4"))
        assertEquals("ftp://host/a:b@c.mp4", MediaFtpUrl.redact("ftp://host/a:b@c.mp4"), "An at-sign in the path is not a login.")
        assertEquals("https://u:p@host/a.mp4", MediaFtpUrl.redact("https://u:p@host/a.mp4"), "Only ftp urls are touched.")
        assertEquals("ftp://bob:***@host/a.mp4", MediaFtpUrl.parse("ftp://bob:hunter2@host/a.mp4")!!.toString())
    }

    @Test
    fun `the server-side policy accepts ftp links`() {
        assertTrue(MediaUrlPolicy.isAllowed("ftp://files.example.com/a.mp4"))
        assertTrue(MediaUrlPolicy.isAllowed("  ftp://files.example.com/a.mp4  "))
        assertFalse(MediaUrlPolicy.isAllowed("ftp://files.example.com/a.mp4%0D%0AQUIT"))
        assertFalse(MediaUrlPolicy.isAllowed("ftp://files.example.com/a.mp4?x=1"))
        assertFalse(MediaUrlPolicy.isAllowed("ftps://files.example.com/a.mp4"))
        assertFalse(MediaUrlPolicy.isAllowed("ftp://files.example.com/" + "a".repeat(MediaUrlPolicy.MAX_URL_LENGTH)))
        // Existing behavior is unchanged.
        assertTrue(MediaUrlPolicy.isAllowed("https://example.com/a.mp4"))
        assertFalse(MediaUrlPolicy.isAllowed("file:///etc/passwd"))
        assertFalse(MediaUrlPolicy.isAllowed("javascript:alert(1)"))
    }

    @Test
    fun `a pasted ftp link is normalized like any other custom link`() {
        assertEquals("ftp://files.example.com/a.mp4", CustomMediaUrls.normalize("<ftp://files.example.com/a.mp4>"))
        assertEquals("ftp://files.example.com/a.mp4", CustomMediaUrls.normalize("FTP://files.example.com/a.mp4"))
        assertNull(CustomMediaUrls.normalize("ftp://files.example.com/a.mp4%0D%0A"))
        assertNull(CustomMediaUrls.normalize("ftps://files.example.com/a.mp4"))
        assertEquals("a", CustomMediaUrls.displayName("ftp://files.example.com/a.mp4"))
        assertEquals("files.example.com", CustomMediaUrls.hostOf("ftp://files.example.com/a.mp4"))
        assertEquals("mp4", CustomMediaUrls.extensionOf("ftp://files.example.com/a.mp4"))
    }
}
