package com.yourvpndead.scanner

import com.yourvpndead.model.ProxyInfo
import com.yourvpndead.model.ProxyType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Определяет тип сервиса на открытом порту:
 * SOCKS5 (с auth / без auth), HTTP proxy, gRPC, или unknown.
 *
 * Использует протокольные handshake'и (RFC 1928 для SOCKS5).
 */
class Socks5Probe {

    companion object {
        private const val HOST = "127.0.0.1"
        private const val TIMEOUT_MS = 1000
    }

    /** Проверить один порт на все типы прокси */
    suspend fun probe(port: Int): ProxyInfo = withContext(Dispatchers.IO) {
        // Попробовать SOCKS5
        probeSocks5(port)?.let { return@withContext it }

        // Попробовать HTTP CONNECT
        probeHTTP(port)?.let { return@withContext it }

        // Попробовать gRPC (HTTP/2 preface)
        probeGrpc(port)?.let { return@withContext it }

        // Неизвестный сервис
        ProxyInfo(port, ProxyType.UNKNOWN, vulnerable = false, details = "Открытый порт, тип не определён")
    }

    /**
     * SOCKS5 handshake по RFC 1928:
     * Клиент: VER(0x05) NMETHODS(2) METHODS(0x00=noauth, 0x02=password)
     * Сервер: VER(0x05) METHOD(выбранный метод)
     */
    private fun probeSocks5(port: Int): ProxyInfo? {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(HOST, port), TIMEOUT_MS)
                socket.soTimeout = TIMEOUT_MS

                val out = socket.getOutputStream()
                val inp = socket.getInputStream()

                // SOCKS5 greeting: предлагаем noauth (0x00) и password (0x02)
                out.write(byteArrayOf(0x05, 0x02, 0x00, 0x02))
                out.flush()

                val resp = ByteArray(2)
                val n = inp.read(resp)

                if (n != 2 || resp[0].toInt() != 0x05) return null

                when (resp[1].toInt() and 0xFF) {
                    0x00 -> ProxyInfo(
                        port, ProxyType.SOCKS5_NO_AUTH, vulnerable = true,
                        details = "SOCKS5 без аутентификации — любое приложение может подключиться!"
                    )
                    0x02 -> ProxyInfo(
                        port, ProxyType.SOCKS5_AUTH_REQUIRED, vulnerable = false,
                        details = "SOCKS5 с аутентификацией — защищён паролем"
                    )
                    0xFF -> ProxyInfo(
                        port, ProxyType.SOCKS5_REJECTED, vulnerable = false,
                        details = "SOCKS5 отклонил все методы — подключение невозможно"
                    )
                    else -> null
                }
            }
        } catch (_: Exception) { null }
    }

    /** HTTP CONNECT проба */
    private fun probeHTTP(port: Int): ProxyInfo? {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(HOST, port), TIMEOUT_MS)
                socket.soTimeout = TIMEOUT_MS

                val out = socket.getOutputStream()
                val inp = socket.getInputStream()

                out.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
                out.flush()

                val buf = ByteArray(256)
                val n = inp.read(buf)
                if (n <= 0) return null
                val response = String(buf, 0, n)

                if (!response.startsWith("HTTP/")) return null

                val code = response.split(" ").getOrNull(1)?.toIntOrNull() ?: return null

                when {
                    code == 200 -> ProxyInfo(
                        port, ProxyType.HTTP_PROXY_OPEN, vulnerable = true,
                        details = "HTTP-прокси без аутентификации (код $code)"
                    )
                    code == 407 -> ProxyInfo(
                        port, ProxyType.HTTP_PROXY_AUTH, vulnerable = false,
                        details = "HTTP-прокси требует аутентификацию (код $code)"
                    )
                    else -> ProxyInfo(
                        port, ProxyType.HTTP_PROXY_AUTH, vulnerable = false,
                        details = "HTTP-прокси ответил кодом $code"
                    )
                }
            }
        } catch (_: Exception) { null }
    }

    /** gRPC проба (HTTP/2 preface) */
    private fun probeGrpc(port: Int): ProxyInfo? {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(HOST, port), TIMEOUT_MS)
                socket.soTimeout = TIMEOUT_MS

                val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                socket.getOutputStream().write(preface.toByteArray())
                socket.getOutputStream().flush()

                val buf = ByteArray(64)
                val n = socket.getInputStream().read(buf)

                // HTTP/2 SETTINGS frame начинается с определённых байт
                if (n >= 9 && buf[3].toInt() == 0x04) {
                    ProxyInfo(
                        port, ProxyType.GRPC_SERVICE, vulnerable = true,
                        details = "gRPC-сервис обнаружен — возможно xray API (HandlerService)"
                    )
                } else null
            }
        } catch (_: Exception) { null }
    }
}
