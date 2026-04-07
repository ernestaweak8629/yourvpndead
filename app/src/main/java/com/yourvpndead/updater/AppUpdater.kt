package com.yourvpndead.updater

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Автообновление через GitHub Releases.
 *
 * 1. Проверяет /releases/latest через GitHub API
 * 2. Сравнивает tag (vN) с текущим versionCode
 * 3. Скачивает APK в cache/updates/
 * 4. Устанавливает через FileProvider + ACTION_VIEW
 */
class AppUpdater {

    companion object {
        private const val GITHUB_API_URL =
            "https://api.github.com/repos/loop-uh/yourvpndead/releases/latest"
        private const val CONNECT_TIMEOUT = 10_000
        private const val READ_TIMEOUT = 15_000
        private const val DOWNLOAD_TIMEOUT = 120_000
    }

    /**
     * Проверить наличие обновления.
     * @param currentVersionCode текущий BuildConfig.VERSION_CODE
     * @return UpdateInfo если доступно обновление, null если нет или ошибка
     */
    suspend fun checkForUpdate(currentVersionCode: Int): UpdateInfo? = withContext(Dispatchers.IO) {
        try {
            val conn = URL(GITHUB_API_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = CONNECT_TIMEOUT
            conn.readTimeout = READ_TIMEOUT
            conn.setRequestProperty("Accept", "application/vnd.github+json")
            conn.setRequestProperty("User-Agent", "YourVPNDead-Android")

            if (conn.responseCode != 200) return@withContext null

            val json = JSONObject(conn.inputStream.bufferedReader().readText())
            val tagName = json.optString("tag_name", "") // e.g., "v12"
            val remoteVersion = tagName.removePrefix("v").toIntOrNull()
                ?: return@withContext null

            // Если удалённая версия не новее — нет обновления
            if (remoteVersion <= currentVersionCode) return@withContext null

            // Найти APK в assets
            val assets = json.optJSONArray("assets") ?: return@withContext null
            val apkAsset = (0 until assets.length())
                .map { assets.getJSONObject(it) }
                .firstOrNull { it.optString("name", "").endsWith(".apk") }
                ?: return@withContext null

            UpdateInfo(
                versionTag = tagName,
                versionCode = remoteVersion,
                downloadUrl = apkAsset.getString("browser_download_url"),
                fileName = apkAsset.getString("name"),
                fileSize = apkAsset.optLong("size", 0),
                releaseNotes = json.optString("body", "").take(500),
                publishedAt = json.optString("published_at", "")
            )
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Скачать APK в cache/updates/.
     * @param onProgress колбэк прогресса (0.0 - 1.0)
     * @return File скачанного APK или null при ошибке
     */
    suspend fun downloadApk(
        context: Context,
        url: String,
        fileName: String,
        onProgress: (Float) -> Unit = {}
    ): File? = withContext(Dispatchers.IO) {
        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = CONNECT_TIMEOUT
            conn.readTimeout = DOWNLOAD_TIMEOUT
            conn.instanceFollowRedirects = true // GitHub redirects to CDN

            val totalSize = conn.contentLengthLong
            val updateDir = File(context.cacheDir, "updates").apply { mkdirs() }

            // Удалить старые APK
            updateDir.listFiles()?.forEach { it.delete() }

            val apkFile = File(updateDir, fileName)

            conn.inputStream.use { input ->
                apkFile.outputStream().use { output ->
                    val buffer = ByteArray(8192)
                    var downloaded = 0L
                    var bytesRead: Int

                    while (input.read(buffer).also { bytesRead = it } != -1) {
                        output.write(buffer, 0, bytesRead)
                        downloaded += bytesRead
                        if (totalSize > 0) {
                            onProgress((downloaded.toFloat() / totalSize).coerceIn(0f, 1f))
                        }
                    }
                }
            }

            onProgress(1f)
            apkFile
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Запустить установку APK через системный установщик.
     * Требует: REQUEST_INSTALL_PACKAGES permission + FileProvider.
     */
    fun installApk(context: Context, apkFile: File) {
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            apkFile
        )
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION
        }
        context.startActivity(intent)
    }
}

/** Информация о доступном обновлении */
data class UpdateInfo(
    val versionTag: String,
    val versionCode: Int,
    val downloadUrl: String,
    val fileName: String,
    val fileSize: Long = 0,
    val releaseNotes: String = "",
    val publishedAt: String = ""
)
