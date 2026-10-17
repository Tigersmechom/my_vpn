package app.myvpn

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLHandshakeException

class ConnectionDiagnosticsTest {
    private val active = VpnStatus(VpnState.UP, Protocol.VLESS_TCP, socksPort = 10808,
        since = 1234, host = "192.0.2.1")

    @Test fun xrayProbesUseExistingSocksAndRequireCompleteDownload() {
        val requests = mutableListOf<ProbeTarget>()
        val report = ConnectionDiagnostics.run(active) { target, proxy ->
            assertEquals(Proxy.Type.SOCKS, proxy.type())
            assertEquals(InetSocketAddress("127.0.0.1", 10808), proxy.address())
            requests += target
            ProbeResponse(target.expectedStatus, target.expectedBytes)
        }
        assertEquals(listOf(0, 65536), requests.map { it.expectedBytes })
        assertTrue(requests.all { it.url.startsWith("https://") })
        assertTrue(report.results.all { it.passed })
        assertTrue(report.summary.contains("загрузка 64 КиБ прошла"))
    }

    @Test fun partialDownloadDoesNotMistakeWorkingSmallRequestForWorkingConnection() {
        val report = ConnectionDiagnostics.run(active) { target, _ ->
            if (target.expectedBytes == 0) ProbeResponse(204, 0)
            else ProbeResponse(200, 16384)
        }
        assertTrue(report.results.first().passed)
        assertEquals(ProbeFailure.INCOMPLETE, report.results.last().failure)
        assertEquals(16384, report.results.last().bytes)
        assertTrue(report.summary.startsWith("Часть проверок"))
    }

    @Test fun timeoutAfterPartialTransferKeepsByteCountAndDoesNotExposeExceptionDetails() {
        val report = ConnectionDiagnostics.run(active) { target, _ ->
            if (target.expectedBytes == 0) ProbeResponse(204, 0)
            else throw ProbeTransferException(16384, SocketTimeoutException("private-data-must-not-appear"))
        }
        val result = report.results.last()
        assertEquals(ProbeFailure.TIMEOUT, result.failure)
        assertTrue(result.message.contains("16384"))
        assertFalse(result.message.contains("private-data"))
    }

    @Test fun probeFailureDoesNotPreventIndependentSecondProbe() {
        var calls = 0
        val report = ConnectionDiagnostics.run(active) { target, _ ->
            calls++
            if (calls == 1) throw UnknownHostException("sensitive detail")
            ProbeResponse(target.expectedStatus, target.expectedBytes)
        }
        assertEquals(2, calls)
        assertEquals(ProbeFailure.DNS, report.results.first().failure)
        assertTrue(report.results.last().passed)
    }

    @Test fun httpsFailuresAndUnexpectedStatusesAreNotSuccess() {
        val failures = listOf(
            SocketTimeoutException() to ProbeFailure.TIMEOUT,
            UnknownHostException() to ProbeFailure.DNS,
            SSLHandshakeException("untrusted certificate") to ProbeFailure.TLS,
            IOException("connection reset") to ProbeFailure.NETWORK,
        )
        for ((error, expected) in failures) {
            val report = ConnectionDiagnostics.run(active) { _, _ -> throw error }
            assertTrue(report.results.all { it.failure == expected })
            assertTrue(report.summary.startsWith("Проверки не прошли"))
        }
        val redirect = ConnectionDiagnostics.run(active) { _, _ -> ProbeResponse(302, 0) }
        assertTrue(redirect.results.all { it.failure == ProbeFailure.HTTP_STATUS })
        val oversized = ConnectionDiagnostics.run(active) { t, _ -> ProbeResponse(t.expectedStatus, t.expectedBytes + 1) }
        assertTrue(oversized.results.all { it.failure == ProbeFailure.OVERSIZED })
    }

    @Test fun amneziaUsesSystemVpnWhileMissingXraySocksNeverFallsBackToDirect() {
        val awg = active.copy(protocol = Protocol.AWG, socksPort = 0)
        ConnectionDiagnostics.run(awg) { target, proxy ->
            assertEquals(Proxy.NO_PROXY, proxy)
            ProbeResponse(target.expectedStatus, target.expectedBytes)
        }
        for (status in listOf(active.copy(socksPort = 0), active.copy(state = VpnState.DOWN),
            active.copy(protocol = null))) {
            var requested = false
            assertThrows(IllegalArgumentException::class.java) {
                ConnectionDiagnostics.run(status) { _, _ ->
                    requested = true
                    ProbeResponse(200, 0)
                }
            }
            assertFalse(requested)
        }
    }

    @Test fun completedResultIsDiscardedIfTunnelChangedDuringProbe() {
        assertTrue(ConnectionDiagnostics.sameConnection(active, active.copy()))
        for (changed in listOf(active.copy(state = VpnState.DOWN), active.copy(since = 1235),
            active.copy(host = "192.0.2.2"), active.copy(socksPort = 10809), active.copy(protocol = Protocol.HY2))) {
            assertFalse(ConnectionDiagnostics.sameConnection(active, changed))
        }
    }
}
