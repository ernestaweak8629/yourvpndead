package com.yourvpndead.scanner

import com.yourvpndead.model.GeoInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URL

/**
 * Геолокация IP-адреса через ip-api.com.
 * Бесплатный API, до 45 запросов/минуту.
 * Возвращает: страну, город, ISP, AS, флаги proxy/hosting.
 */
class GeoLocator {

    /**
     * Геолоцировать IP-адрес.
     * @param ip IPv4-адрес для геолокации
     * @return GeoInfo или null при ошибке
     */
    suspend fun locate(ip: String): GeoInfo? = withContext(Dispatchers.IO) {
        try {
            // fields=66846719 включает все поля включая proxy, hosting
            val url = "http://ip-api.com/json/$ip?fields=66846719&lang=ru"
            val response = URL(url).readText()
            val json = JSONObject(response)

            if (json.optString("status") != "success") return@withContext null

            GeoInfo(
                ip = ip,
                country = json.optString("country", "?"),
                countryCode = json.optString("countryCode", ""),
                city = json.optString("city", "?"),
                isp = json.optString("isp", "?"),
                org = json.optString("org", "?"),
                asNumber = json.optString("as", "?"),
                isProxy = json.optBoolean("proxy", false),
                isHosting = json.optBoolean("hosting", false)
            )
        } catch (_: Exception) {
            null
        }
    }
}
