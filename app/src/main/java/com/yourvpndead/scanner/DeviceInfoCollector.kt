package com.yourvpndead.scanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import com.yourvpndead.model.DeviceFingerprint
import com.yourvpndead.model.NetInterface
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.NetworkInterface
import java.net.URL

/**
 * Собирает информацию об устройстве — то, что шпионское ПО
 * может получить БЕЗ root и с минимальными разрешениями.
 */
class DeviceInfoCollector(private val context: Context) {

    /** Собрать полный отпечаток устройства */
    suspend fun collect(): DeviceFingerprint = withContext(Dispatchers.IO) {
        DeviceFingerprint(
            model = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            androidVersion = Build.VERSION.RELEASE,
            sdkVersion = Build.VERSION.SDK_INT,
            board = Build.BOARD,
            hardware = Build.HARDWARE,
            buildFingerprint = Build.FINGERPRINT,
            isVpnActive = isVpnActive(),
            networkInterfaces = enumerateInterfaces(),
            directIP = getDirectIP()
        )
    }

    /**
     * Определить, активен ли VPN.
     * Использует ConnectivityManager.TRANSPORT_VPN.
     * Требует: ACCESS_NETWORK_STATE
     */
    private fun isVpnActive(): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(network) ?: return false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Перечислить все сетевые интерфейсы.
     * tun0 = VPN TUN интерфейс
     * wlan0 = Wi-Fi
     * rmnet0 = мобильная сеть
     */
    private fun enumerateInterfaces(): List<NetInterface> {
        return try {
            NetworkInterface.getNetworkInterfaces()?.asSequence()?.map { iface ->
                NetInterface(
                    name = iface.name,
                    displayName = iface.displayName,
                    isUp = iface.isUp,
                    ips = iface.inetAddresses.asSequence()
                        .mapNotNull { it.hostAddress }
                        .filter { !it.contains("%") } // убрать IPv6 scope ID
                        .toList()
                )
            }?.toList() ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Получить прямой IP (без VPN) через api.ipify.org.
     * Если VPN активен, вернёт IP VPN-сервера (через системный маршрут).
     * Если шпион подключится через SOCKS5 — может получить другой IP.
     */
    private fun getDirectIP(): String? {
        return try {
            URL("https://api.ipify.org").readText().trim()
        } catch (_: Exception) {
            null
        }
    }
}
