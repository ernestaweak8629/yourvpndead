package com.yourvpndead.scanner

import com.yourvpndead.model.ListeningPort
import com.yourvpndead.model.VpnClientGuess
import java.io.File

class ProcNetScanner {

    companion object {
        private const val STATE_LISTEN = "0A"

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
            1080 to "Generic SOCKS5 (sing-box / Throne default)"
        )

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

    fun scanListeningPorts(): List<ListeningPort> {
        val tcpPorts = parseProcNet("/proc/net/tcp")
        val tcp6Ports = parseProcNet("/proc/net/tcp6")
        return (tcpPorts + tcp6Ports).distinctBy { it.port }
    }

    fun identifyVpnClient(ports: List<ListeningPort>): List<VpnClientGuess> {
        val guesses = mutableListOf<VpnClientGuess>()
        val portNumbers = ports.map { it.port }.toSet()

        if (10808 in portNumbers) {
            val confidence = when {
                10809 in portNumbers && 19085 in portNumbers -> 95
                10809 in portNumbers -> 85
                else -> 70
            }
            guesses.add(VpnClientGuess(
                name = "xray-core (v2rayNG / v2RayTun)",
                confidence = confidence,
                evidence = buildList {
                    add("SOCKS5 :10808")
                    if (10809 in portNumbers) add("HTTP :10809")
                    if (19085 in portNumbers) add("Stats API :19085")
                }
            ))
        }

        if (2080 in portNumbers) {
            guesses.add(VpnClientGuess(
                name = "sing-box (NekoBox / Throne / Husi)",
                confidence = 80,
                evidence = listOf("Mixed :2080")
            ))
        }

        if (7891 in portNumbers || 7890 in portNumbers) {
            val confidence = when {
                9090 in portNumbers -> 95
                7890 in portNumbers && 7891 in portNumbers -> 90
                else -> 75
            }
            guesses.add(VpnClientGuess(
                name = "Clash / mihomo",
                confidence = confidence,
                evidence = buildList {
                    if (7890 in portNumbers) add("HTTP :7890")
                    if (7891 in portNumbers) add("SOCKS5 :7891")
                    if (9090 in portNumbers) add("API :9090")
                }
            ))
        }

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

        if (19090 in portNumbers) {
            guesses.add(VpnClientGuess(
                name = "sing-box Clash API (LEAK RISK)",
                confidence = 90,
                evidence = listOf("Clash API :19090")
            ))
        }

        return guesses
    }

    fun scanEstablishedConnections(): List<EstablishedConnection> {
        val connections = mutableListOf<EstablishedConnection>()
        connections.addAll(parseProcNetEstablished("/proc/net/tcp", false, "01"))
        connections.addAll(parseProcNetEstablished("/proc/net/tcp6", true, "01"))
        connections.addAll(parseProcNetEstablished("/proc/net/udp", false, null))
        connections.addAll(parseProcNetEstablished("/proc/net/udp6", true, null))
        return connections
            .filter { isPublicIp(it.remoteIp) }
            .distinctBy { it.remoteIp + ":" + it.remotePort }
            .sortedByDescending { it.vpnLikelihood }
    }

    private fun parseProcNetEstablished(path: String, isIpv6: Boolean, stateFilter: String?): List<EstablishedConnection> {
        return try {
            val file = File(path)
            if (!file.canRead()) return emptyList()
            file.readLines().drop(1).mapNotNull { line ->
                parseEstablishedLine(line, isIpv6, stateFilter, path)
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun parseEstablishedLine(line: String, isIpv6: Boolean, stateFilter: String?, sourcePath: String): EstablishedConnection? {
        val parts = line.trim().split("\\s+".toRegex())
        if (parts.size < 10) return null
        val localAddr = parts[1]
        val remoteAddr = parts[2]
        val state = parts[3]
        val uid = parts[7].toIntOrNull() ?: return null
        if (stateFilter != null && state != stateFilter) return null
        val colonIdx = remoteAddr.lastIndexOf(':')
        if (colonIdx < 0) return null
        val hexIp = remoteAddr.substring(0, colonIdx)
        val hexPort = remoteAddr.substring(colonIdx + 1)
        val remotePort = hexPort.toIntOrNull(16) ?: return null
        if (remotePort == 0 && hexIp.all { it == '0' }) return null
        val remoteIp = if (isIpv6) hexToIpv6(hexIp) else hexToIpv4(hexIp)
        if (remoteIp == null) return null
        val localColonIdx = localAddr.lastIndexOf(':')
        val localPort = if (localColonIdx >= 0) localAddr.substring(localColonIdx + 1).toIntOrNull(16) ?: 0 else 0
        val protocol = if (sourcePath.contains("udp")) "UDP" else "TCP"
        val vpnLikelihood = calculateVpnLikelihood(remoteIp, remotePort, protocol)
        return EstablishedConnection(
            remoteIp = remoteIp, remotePort = remotePort, localPort = localPort,
            protocol = protocol, uid = uid, state = state,
            vpnLikelihood = vpnLikelihood, serverGuess = guessServerType(remotePort, protocol)
        )
    }

    private fun hexToIpv4(hex: String): String? {
        if (hex.length != 8) return null
        return try {
            val n = hex.toLong(16)
            "${n and 0xFF}.${(n shr 8) and 0xFF}.${(n shr 16) and 0xFF}.${(n shr 24) and 0xFF}"
        } catch (e: Exception) { null }
    }

    private fun hexToIpv6(hex: String): String? {
        if (hex.length != 32) return null
        return try {
            val groups = (0 until 32 step 8).map { i ->
                val group = hex.substring(i, i + 8)
                val n = group.toLong(16)
                ((n and 0xFF) shl 24) or (((n shr 8) and 0xFF) shl 16) or (((n shr 16) and 0xFF) shl 8) or ((n shr 24) and 0xFF)
            }
            if (groups[0] == 0L && groups[1] == 0L && groups[2] == 0xFFFF0000L) {
                val ipv4 = groups[3]
                return "${(ipv4 shr 24) and 0xFF}.${(ipv4 shr 16) and 0xFF}.${(ipv4 shr 8) and 0xFF}.${ipv4 and 0xFF}"
            }
            groups.joinToString(":") { "%08X".format(it) }.lowercase()
        } catch (e: Exception) { null }
    }

    private fun isPublicIp(ip: String): Boolean {
        if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.")) return false
        if (ip.startsWith("172.")) {
            val second = ip.split(".").getOrNull(1)?.toIntOrNull()
            if (second != null && second in 16..31) return false
        }
        if (ip.startsWith("0.") || ip.startsWith("224.") || ip.startsWith("239.") || ip.startsWith("255.")) return false
        if (ip == "::1" || ip == "::" || ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd")) return false
        return true
    }

    private fun calculateVpnLikelihood(ip: String, port: Int, protocol: String): Int {
        var score = 30
        when (port) {
            51820, 51821 -> score += 60
            1194 -> score += 50
            443 -> score += 20
            500, 4500 -> score += 50
            1701 -> score += 40
            1723 -> score += 40
        }
        if (protocol == "UDP" && port > 1024 && port != 8443) score += 30
        if (ip.startsWith("185.") || ip.startsWith("45.") || ip.startsWith("104.")) score += 10
        return score.coerceAtMost(100)
    }

    private fun guessServerType(port: Int, protocol: String): String {
        return when {
            port == 51820 || port == 51821 -> "WireGuard / Amnezia"
            port == 1194 && protocol == "UDP" -> "OpenVPN (UDP)"
            port == 1194 && protocol == "TCP" -> "OpenVPN (TCP)"
            port == 443 && protocol == "TCP" -> "VLESS / Trojan / HTTPS VPN"
            port == 500 || port == 4500 -> "IPSec / IKEv2"
            port == 1701 -> "L2TP"
            port == 1723 -> "PPTP"
            port == 80 -> "HTTP (splithttp)"
            protocol == "UDP" && port > 10000 -> "WireGuard (custom port)"
            else -> "Unknown ($protocol:$port)"
        }
    }

    private fun parseProcNet(path: String): List<ListeningPort> {
        return try {
            val file = File(path)
            if (!file.canRead()) return emptyList()
            file.readLines().drop(1).mapNotNull { line -> parseLine(line, path.contains("6")) }
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun parseLine(line: String, isIpv6: Boolean): ListeningPort? {
        val parts = line.trim().split("\\s+".toRegex())
        if (parts.size < 10) return null
        val localAddr = parts[1]
        val state = parts[3]
        val uid = parts[7].toIntOrNull() ?: return null
        if (state != STATE_LISTEN) return null
        val colonIdx = localAddr.lastIndexOf(':')
        if (colonIdx < 0) return null
        val hexIp = localAddr.substring(0, colonIdx)
        val hexPort = localAddr.substring(colonIdx + 1)
        val port = hexPort.toIntOrNull(16) ?: return null
        val isLocalhost = if (isIpv6) {
            hexIp == "00000000000000000000000000000000" || hexIp == "00000000000000000000000001000000" || hexIp.endsWith("0100007F")
        } else {
            hexIp == "0100007F" || hexIp == "00000000"
        }
        val listenAll = if (isIpv6) hexIp == "00000000000000000000000000000000" else hexIp == "00000000"
        val clientGuess = CLIENT_SIGNATURES[port]
        return ListeningPort(
            port = port, uid = uid, isLocalhost = isLocalhost && !listenAll,
            listenAll = listenAll, clientGuess = clientGuess,
            source = if (isIpv6) "tcp6" else "tcp"
        )
    }
}
