package com.yourvpndead.scanner

import com.yourvpndead.model.ListeningPort
import com.yourvpndead.model.VpnClientGuess
import java.io.File

/**
 * Парсер /proc/net/tcp и /proc/net/udp для fingerprinting VPN-клиентов.
 *
 * Формат /proc/net/tcp:
 * sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
 *
 * local_address = hex IP:hex PORT (например 0100007F:2A30 = 127.0.0.1:10808)
 * st = 0A (LISTEN)
 * uid = UID процесса-владельца
 *
 * Это позволяет определить:
 * 1. Какие порты слушают на localhost
 * 2. Какой UID (= какое приложение) владеет портом
 * 3. По паттерну портов — какой VPN-клиент запущен
 */
class ProcNetScanner {

    companion object {
        private const val STATE_LISTEN = "0A"

        /** Известные паттерны портов VPN-клиентов */
        val CLIENT_SIGNATURES = mapOf(
            10808 to "v2rayNG / v2RayTun / XrayFluent (xray SOCKS5)",
            10809 to "v2rayNG / XrayFluent (xray HTTP)",
            2080 to "NekoBox / Throne (sing-box mixed)",
            7890 to "Clash / mihomo (HTTP proxy)",
            7891 to "Clash / mihomo (SOCKS5)",
            10801 to "Clash / mihomo (mixed)",
            3066 to "Karing (HTTP/SOCKS5 full proxy)",
            3067 to "Karing (SOCKS5 rule-based)",
            19085 to "xray Stats API",
            19090 to "sing-box Clash API",
            9090 to "Clash / mihomo API",
            1080 to "Generic SOCKS5 (sing-box / Throne default)",
        )

        /** Установленное соединение из /proc/net */
        data class EstablishedConnection(
            val remoteIp: String,
            val remotePort: Int,
            val localPort: Int = 0,
            val protocol: String = "TCP",
            val uid: Int = 0,
            val state: String = "",
            val vpnLikelihood: Int = 0,
            val serverGuess: String = ""
        )
    }

    /**
     * Прочитать /proc/net/tcp и найти все LISTENING порты на localhost.
     * Работает без root на большинстве Android версий.
     */
    fun scanListeningPorts(): List<ListeningPort> {
        val tcpPorts = parseProcNet("/proc/net/tcp")
        val tcp6Ports = parseProcNet("/proc/net/tcp6")
        return (tcpPorts + tcp6Ports).distinctBy { it.port }
    }

    /**
     * Идентифицировать VPN-клиент по паттерну открытых портов.
     */
    fun identifyVpnClient(ports: List<ListeningPort>): List<VpnClientGuess> {
        val guesses = mutableListOf<VpnClientGuess>()
        val portNumbers = ports.map { it.port }.toSet()

        // xray-based (v2rayNG, v2RayTun)
        if (10808 in portNumbers) {
            val confidence = when {
                10809 in portNumbers && 19085 in portNumbers -> 95
                10809 in portNumbers -> 85
                else -> 70
            }
            guesses.add(VpnClientGuess(
                name = "xray-core клиент (v2rayNG / v2RayTun)",
                confidence = confidence,
                evidence = buildList {
                    add("SOCKS5 :10808")
                    if (10809 in portNumbers) add("HTTP :10809")
                    if (19085 in portNumbers) add("Stats API :19085")
                }
            ))
        }

        // sing-box (NekoBox, Husi, SFA)
        if (2080 in portNumbers) {
            guesses.add(VpnClientGuess(
                name = "sing-box клиент (NekoBox / Throne / Husi)",
                confidence = 80,
                evidence = listOf("Mixed :2080")
            ))
        }

        // Clash / mihomo
        if (7891 in portNumbers || 7890 in portNumbers) {
            val confidence = when {
                9090 in portNumbers -> 95
                7890 in portNumbers && 7891 in portNumbers -> 90
                else -> 75
            }
            guesses.add(VpnClientGuess(
                name = "Clash / mihomo клиент",
                confidence = confidence,
                evidence = buildList {
                    if (7890 in portNumbers) add("HTTP :7890")
                    if (7891 in portNumbers) add("SOCKS5 :7891")
                    if (9090 in portNumbers) add("API :9090")
                }
            ))
        }

        // Karing
        if (3067 in portNumbers || 3066 in portNumbers) {
            guesses.add(VpnClientGuess(
                name = "Karing",
                confidence = 85,
                evidence = buildList {
                    if (3067 in portNumbers) add("SOCKS5 :3067")
                    if (3066 in portNumbers) add("Full proxy :3066")
                }
            ))
        }

        // sing-box Clash API
        if (19090 in portNumbers) {
            guesses.add(VpnClientGuess(
                name = "sing-box Clash API (LEAK RISK)",
                confidence = 90,
                evidence = listOf("Clash API :19090 — GET /connections раскрывает IP серверов!")
            ))
        }

        return guesses
    }

    /**
     * Сканировать ESTABLISHED-соединения в /proc/net/tcp и /proc/net/udp.
     * Ищем соединения с публичными IP — это вероятные VPN-серверы.
     *
     * Работает для ВСЕХ типов VPN:
     * - WireGuard/Amnezia → UDP к серверу (часто порт 51820)
     * - OpenVPN → TCP/UDP к серверу (часто порт 1194)
     * - xray/VLESS/Trojan → TCP к серверу (часто порт 443)
     */
    fun scanEstablishedConnections(): List<Companion.EstablishedConnection> {
        val connections = mutableListOf<Companion.EstablishedConnection>()

        // TCP established (state 01)
        connections.addAll(parseProcNetEstablished("/proc/net/tcp", false, "01"))
        connections.addAll(parseProcNetEstablished("/proc/net/tcp6", true, "01"))

        // UDP "connected" — any entry with non-zero remote address
        connections.addAll(parseProcNetEstablished("/proc/net/udp", false, null))
        connections.addAll(parseProcNetEstablished("/proc/net/udp6", true, null))

        return connections
            .filter { isPublicIp(it.remoteIp) }
            .distinctBy { "${it.remoteIp}:${it.remotePort}" }
            .sortedByDescending { it.vpnLikelihood }
    }

    /**
     * Парсить /proc/net/* для established/connected записей.
     * @param stateFilter если не null — фильтровать по state (TCP: "01" = ESTABLISHED)
     *                    если null — берём все с non-zero remote (UDP)
     */
    private fun parseProcNetEstablished(
        path: String,
        isIpv6: Boolean,
        stateFilter: String?
    ): List<Companion.EstablishedConnection> {
        return try {
            val file = File(path)
            if (!file.canRead()) return emptyList()

            file.readLines().drop(1).mapNotNull { line ->
                parseEstablishedLine(line, isIpv6, stateFilter, path)
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun parseEstablishedLine(
        line: String,
        isIpv6: Boolean,
        stateFilter: String?,
        sourcePath: String
    ): Companion.EstablishedConnection? {
        val parts = line.trim().split("\\s+".toRegex())
        if (parts.size < 10) return null

        val localAddr = parts[1]
        val remoteAddr = parts[2]
        val state = parts[3]
        val uid = parts[7].toIntOrNull() ?: return null

        // Filter by state if specified
        if (stateFilter != null && state != stateFilter) return null

        // Parse remote address
        val colonIdx = remoteAddr.lastIndexOf(':')
        if (colonIdx < 0) return null

        val hexIp = remoteAddr.substring(0, colonIdx)
        val hexPort = remoteAddr.substring(colonIdx + 1)
        val remotePort = hexPort.toIntOrNull(16) ?: return null

        // Skip entries with no remote (0.0.0.0:0)
        if (remotePort == 0 && hexIp.all { it == '0' }) return null

        val remoteIp = if (isIpv6) hexToIpv6(hexIp) else hexToIpv4(hexIp)
        if (remoteIp == null) return null

        // Parse local address for context
        val localColonIdx = localAddr.lastIndexOf(':')
        val localPort = if (localColonIdx >= 0) {
            localAddr.substring(localColonIdx + 1).toIntOrNull(16) ?: 0
        } else 0

        val protocol = if (sourcePath.contains("udp")) "UDP" else "TCP"
        val vpnLikelihood = calculateVpnLikelihood(remoteIp, remotePort, protocol)

        return Companion.EstablishedConnection(
            remoteIp = remoteIp,
            remotePort = remotePort,
            localPort = localPort,
            protocol = protocol,
            uid = uid,
            state = state,
            vpnLikelihood = vpnLikelihood,
            serverGuess = guessServerType(remotePort, protocol)
        )
    }

    /** Конвертация hex IP (little-endian) из /proc/net в dotted notation */
    private fun hexToIpv4(hex: String): String? {
        if (hex.length != 8) return null
        return try {
            val n = hex.toLong(16)
            "${n and 0xFF}.${(n shr 8) and 0xFF}.${(n shr 16) and 0xFF}.${(n shr 24) and 0xFF}"
        } catch (_: Exception) { null }
    }

    /** Конвертация IPv6 hex из /proc/net */
    private fun hexToIpv6(hex: String): String? {
        if (hex.length != 32) return null
        return try {
            // /proc/net/tcp6 stores IPv6 as 4 groups of 32-bit little-endian hex
            // e.g., "0000000000000000FFFF00000100007F" for ::ffff:127.0.0.1
            val groups = (0 until 32 step 8).map { i ->
                val group = hex.substring(i, i + 8)
                // Each 8-char group is a 32-bit little-endian value
                val n = group.toLong(16)
                val be = ((n and 0xFF) shl 24) or
                         (((n shr 8) and 0xFF) shl 16) or
                         (((n shr 16) and 0xFF) shl 8) or
                         ((n shr 24) and 0xFF)
                be
            }

            // Check if it's IPv4-mapped (::ffff:x.x.x.x)
            if (groups[0] == 0L && groups[1] == 0L && groups[2] == 0xFFFF0000L) {
                val ipv4 = groups[3]
                return "${(ipv4 shr 24) and 0xFF}.${(ipv4 shr 16) and 0xFF}.${(ipv4 shr 8) and 0xFF}.${ipv4 and 0xFF}"
            }

            // Return full IPv6
            groups.joinToString(":") { "%08X".format(it) }
                .replace(Regex("(0000:)+"), ":")
                .replace(Regex("^:"), "")
                .replace(Regex(":$"), "")
                .lowercase()
        } catch (_: Exception) { null }
    }

    /** Проверить что IP — публичный (не localhost, не LAN, не multicast) */
    private fun isPublicIp(ip: String): Boolean {
        if (ip.startsWith("127.")) return false
        if (ip.startsWith("10.")) return false
        if (ip.startsWith("192.168.")) return false
        if (ip.startsWith("172.") && run {
            val second = ip.split(".").getOrNull(1)?.toIntOrNull() ?: return@run false
            second in 16..31
        }) return false
        if (ip.startsWith("0.")) return false
        if (ip.startsWith("224.") || ip.startsWith("239.") || ip.startsWith("255.")) return false
        if (ip == "::1" || ip == "::") return false
        if (ip.startsWith("fe80:")) return false  // link-local IPv6
        if (ip.startsWith("fc") || ip.startsWith("fd")) return false  // ULA IPv6
        return true
    }

    /** Оценить вероятность что соединение = VPN-сервер (0-100) */
    private fun calculateVpnLikelihood(ip: String, port: Int, protocol: String): Int {
        var score = 30 // base score for any public IP connection

        // Known VPN ports
        when (port) {
            51820, 51821 -> score += 60 // WireGuard
            1194 -> score += 50 // OpenVPN
            443 -> score += 20  // VLESS/Trojan/HTTPS (common but not conclusive)
            500, 4500 -> score += 50 // IPSec
            1701 -> score += 40 // L2TP
            1723 -> score += 40 // PPTP
        }

        // UDP to non-standard high port = likely WireGuard
        if (protocol == "UDP" && port > 1024 && port != 8443) {
            score += 30
        }

        // Known hosting ranges (simplified check)
        if (ip.startsWith("185.") || ip.startsWith("45.") || ip.startsWith("104.")) {
            score += 10 // common VPS ranges
        }

        return score.coerceAtMost(100)
    }

    /** Угадать тип сервера по порту */
    private fun guessServerType(port: Int, protocol: String): String {
        return when {
            port == 51820 || port == 51821 -> "WireGuard / Amnezia"
            port == 1194 && protocol == "UDP" -> "OpenVPN (UDP)"
            port == 1194 && protocol == "TCP" -> "OpenVPN (TCP)"
            port == 443 && protocol == "TCP" -> "VLESS / Trojan / HTTPS VPN"
            port == 500 || port == 4500 -> "IPSec / IKEv2"
            port == 1701 -> "L2TP"
            port == 1723 -> "PPTP"
            port == 80 -> "HTTP (может быть splithttp)"
            protocol == "UDP" && port > 10000 -> "WireGuard (нестандартный порт)"
            else -> "Неизвестный ($protocol:$port)"
        }
    }

    /**
     * Парсить /proc/net/tcp или /proc/net/tcp6.
     * Возвращает только LISTENING порты на localhost.
     */
    private fun parseProcNet(path: String): List<ListeningPort> {
        return try {
            val file = File(path)
            if (!file.canRead()) return emptyList()

            file.readLines().drop(1) // пропустить заголовок
                .mapNotNull { line -> parseLine(line, path.contains("6")) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun parseLine(line: String, isIpv6: Boolean): ListeningPort? {
        val parts = line.trim().split("\\s+".toRegex())
        if (parts.size < 10) return null

        val localAddr = parts[1]  // hex_ip:hex_port
        val state = parts[3]
        val uid = parts[7].toIntOrNull() ?: return null

        // Только LISTENING (state = 0A)
        if (state != STATE_LISTEN) return null

        val colonIdx = localAddr.lastIndexOf(':')
        if (colonIdx < 0) return null

        val hexIp = localAddr.substring(0, colonIdx)
        val hexPort = localAddr.substring(colonIdx + 1)
        val port = hexPort.toIntOrNull(16) ?: return null

        // Проверяем что это localhost
        val isLocalhost = if (isIpv6) {
            hexIp == "00000000000000000000000000000000" || // ::
            hexIp == "00000000000000000000000001000000" || // ::1
            hexIp.endsWith("0100007F")                     // ::ffff:127.0.0.1
        } else {
            hexIp == "0100007F" || // 127.0.0.1
            hexIp == "00000000"    // 0.0.0.0 (слушает на всех)
        }

        val listenAll = if (isIpv6) {
            hexIp == "00000000000000000000000000000000"
        } else {
            hexIp == "00000000"
        }

        val clientGuess = CLIENT_SIGNATURES[port]

        return ListeningPort(
            port = port,
            uid = uid,
            isLocalhost = isLocalhost && !listenAll,
            listenAll = listenAll,
            clientGuess = clientGuess,
            source = if (isIpv6) "tcp6" else "tcp"
        )
    }
}
