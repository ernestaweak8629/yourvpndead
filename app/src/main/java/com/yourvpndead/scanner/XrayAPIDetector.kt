package com.yourvpndead.scanner

import com.yourvpndead.model.XrayAPIInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Обнаруживает xray gRPC API на localhost.
 *
 * xray API (HandlerService) позволяет дампить конфигурации,
 * включая ключи шифрования, IP серверов, SNI — без аутентификации.
 * Именно это делает клиент Happ.
 */
class XrayAPIDetector {

    companion object {
        private const val HOST = "127.0.0.1"

        /** Типичные порты xray API */
        val API_PORTS = listOf(
            10085,  // дефолт во многих конфигах
            19085,  // XrayFluent
            23456,  // альтернативный
            8001,   // альтернативный
            62789,  // нестандартный
            8080,   // общий
            10086,  // альтернативный
        )
    }

    /**
     * Проверить все известные API-порты.
     * @return информация об API или null если не найден
     */
    suspend fun detect(): XrayAPIInfo? = withContext(Dispatchers.IO) {
        API_PORTS.map { port ->
            async { probeApiPort(port) }
        }.awaitAll().filterNotNull().firstOrNull()
    }

    /**
     * Проверить конкретный порт на наличие gRPC (HTTP/2).
     *
     * gRPC использует HTTP/2. Отправляем connection preface:
     * "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
     * Если получаем HTTP/2 SETTINGS frame (type=0x04) — это gRPC.
     */
    private fun probeApiPort(port: Int): XrayAPIInfo? {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(HOST, port), 500)
                socket.soTimeout = 1000

                val out = socket.getOutputStream()
                val inp = socket.getInputStream()

                // HTTP/2 connection preface (RFC 7540, Section 3.5)
                val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                out.write(preface.toByteArray())
                out.flush()

                // HTTP/2 SETTINGS frame: length(3 bytes) + type(1 byte=0x04) + ...
                val buf = ByteArray(64)
                val n = inp.read(buf)

                if (n >= 9) {
                    // Проверяем type byte (позиция 3) на SETTINGS (0x04)
                    val frameType = buf[3].toInt() and 0xFF
                    if (frameType == 0x04) {
                        return XrayAPIInfo(
                            port = port,
                            accessible = true,
                            details = buildString {
                                append("xray gRPC API обнаружен на порту $port!\n")
                                append("Возможные сервисы: HandlerService, StatsService\n")
                                append("HandlerService позволяет дампить ключи, IP, SNI!")
                            }
                        )
                    }
                }

                null
            }
        } catch (_: Exception) {
            null
        }
    }
}
