package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
)

class PayloadRepository(private val context: Context) {

    /**
     * Load the target manifest, preferring the local cache, then the bundled
     * asset, and finally the remote repository. The cache is populated by
     * [refreshPayloads].
     */
    fun loadTargets(): List<TargetProfile> {
        val manifestBytes = loadCachedManifest()
            ?: loadBundledManifest()
            ?: loadRemoteManifest()
        return SupportManifest.parse(manifestBytes).targets
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile = loadTargets()
        .firstOrNull { it.matches(snapshot) }
        ?: error(context.getString(R.string.repo_no_profile))

    fun resolveTarget(profileId: String): TargetProfile = loadTargets()
        .firstOrNull { it.profileId == profileId }
        ?: error(context.getString(R.string.repo_profile_missing, profileId))

    /**
     * Resolve the payload files for a profile. Uses cached files on disk when
     * they match the expected size, falls back to bundled assets, and downloads
     * from the remote repository only as a last resort.
     */
    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val exploitFile = File(directory, "cve-2026-43499-app.so")
        val ksudFile = File(directory, "ksud-s25u-kdp")

        val exploit = resolveArtifact(
            profile.exploit,
            exploitFile,
            "bundled/${profile.profileId}/cve-2026-43499-app.so",
            context.getString(R.string.artifact_exploit),
            onProgress,
        )
        val kernelSu = resolveArtifact(
            profile.kernelSu,
            ksudFile,
            "bundled/${profile.profileId}/ksud-s25u-kdp",
            context.getString(R.string.artifact_kernelsu),
            onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        return VerifiedPayloads(profile, exploit, kernelSu)
    }

    /**
     * Fetch the latest manifest and payload files from the remote repository,
     * replacing the local cache. Returns true when new data was downloaded.
     */
    fun refreshPayloads(onProgress: (String) -> Unit): Boolean {
        onProgress(context.getString(R.string.payload_refresh_checking))
        val remoteManifest = loadRemoteManifest()
        val cachedManifest = loadCachedManifest()

        val changed = !cachedManifest.contentEquals(remoteManifest)
        // Always write the manifest so the timestamp updates
        cachedManifestFile().parentFile?.mkdirs()
        cachedManifestFile().writeBytes(remoteManifest)

        val targets = SupportManifest.parse(remoteManifest).targets
        for (profile in targets) {
            val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
            val exploitFile = File(directory, "cve-2026-43499-app.so")
            val ksudFile = File(directory, "ksud-s25u-kdp")

            if (!exploitFile.exists() || exploitFile.length() != profile.exploit.size) {
                downloadArtifact(
                    profile.exploit,
                    exploitFile,
                    context.getString(R.string.artifact_exploit),
                    onProgress,
                )
            }
            if (!ksudFile.exists() || ksudFile.length() != profile.kernelSu.size) {
                downloadArtifact(
                    profile.kernelSu,
                    ksudFile,
                    context.getString(R.string.artifact_kernelsu),
                    onProgress,
                )
            }
        }
        onProgress(context.getString(R.string.payload_refresh_done))
        return changed
    }

    // ------------------------------------------------------------------
    // Manifest resolution: cached → bundled → remote
    // ------------------------------------------------------------------

    private fun cachedManifestFile() = File(context.filesDir, "payloads/targets-v3.json")

    private fun loadCachedManifest(): ByteArray? {
        val file = cachedManifestFile()
        return if (file.exists()) file.readBytes() else null
    }

    private fun loadBundledManifest(): ByteArray? = runCatching {
        context.assets.open("bundled/targets-v3.json").use { it.readBytes() }
    }.getOrNull()

    private fun loadRemoteManifest(): ByteArray {
        val commit = resolveMainCommit()
        return downloadBytes(rawUrl(commit, "support/targets-v3.json"), MAX_MANIFEST_BYTES)
    }

    // ------------------------------------------------------------------
    // Artifact resolution: cached → bundled → remote
    // ------------------------------------------------------------------

    /**
     * Returns a usable file for the given artifact, checking cached (on disk),
     * then bundled (in assets), then remote (download). When using a bundled
     * asset, it is copied to the cache directory so subsequent calls skip the
     * asset extraction.
     */
    private fun resolveArtifact(
        artifact: RemoteArtifact,
        destination: File,
        assetPath: String,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        // 1. Cached on disk with correct size
        if (destination.exists() && destination.length() == artifact.size) {
            onProgress(context.getString(R.string.payload_cached, label))
            return destination
        }

        // 2. Bundled in assets
        val bundled = extractBundledArtifact(assetPath, destination, artifact.size)
        if (bundled != null) {
            onProgress(context.getString(R.string.payload_bundled, label))
            return bundled
        }

        // 3. Download from remote
        return downloadArtifact(artifact, destination, label, onProgress)
    }

    /**
     * Tries to copy a bundled asset to [destination]. Returns the file on
     * success, or null if the asset does not exist or does not match the
     * expected size.
     */
    private fun extractBundledArtifact(assetPath: String, destination: File, expectedSize: Long): File? {
        return try {
            destination.parentFile?.mkdirs()
            val temporary = File(destination.parentFile, "${destination.name}.asset")
            context.assets.open(assetPath).use { input ->
                FileOutputStream(temporary).use { output ->
                    input.copyTo(output)
                    output.fd.sync()
                }
            }
            if (temporary.length() != expectedSize) {
                temporary.delete()
                return null
            }
            if (destination.exists()) destination.delete()
            if (temporary.renameTo(destination)) destination else null
        } catch (_: IOException) {
            null
        }
    }

    // ------------------------------------------------------------------
    // Remote download (unchanged logic)
    // ------------------------------------------------------------------

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(context.getString(R.string.repo_downloading, label))
        val temporary = File(destination.parentFile, "${destination.name}.part")
        val connection = open(artifact.url)
        require(connection.contentLengthLong == -1L || connection.contentLengthLong == artifact.size) {
            context.getString(R.string.repo_size_mismatch, label)
        }
        var total = 0L
        connection.inputStream.use { input ->
            FileOutputStream(temporary).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        connection.disconnect()
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
        if (destination.exists()) destination.delete()
        require(temporary.renameTo(destination)) {
            context.getString(R.string.repo_finalize_failed, label)
        }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    private fun resolveMainCommit(): String {
        val response = downloadBytes(COMMIT_API_URL, MAX_COMMIT_RESPONSE_BYTES)
        val commit = JSONObject(response.toString(Charsets.UTF_8))
            .getJSONObject("object")
            .getString("sha")
        require(commit.matches(Regex("[0-9a-f]{40}"))) { context.getString(R.string.repo_commit_invalid) }
        return commit
    }

    private fun rawUrl(commit: String, path: String) = "$RAW_REPOSITORY/$commit/$path"

    private fun downloadBytes(url: String, maximum: Int): ByteArray {
        val connection = open(url)
        val bytes = connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        connection.disconnect()
        return bytes
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "S25URoot/${BuildConfig.VERSION_NAME}")
            connect()
            require(responseCode == HttpURLConnection.HTTP_OK) { "HTTP $responseCode" }
        }

    companion object {
        private const val COMMIT_API_URL =
            "https://api.github.com/repos/aayy-dev/Root-My-Galaxy-Payloads/git/ref/heads/testing"
        private const val RAW_REPOSITORY =
            "https://raw.githubusercontent.com/aayy-dev/Root-My-Galaxy-Payloads"
        private const val MAX_COMMIT_RESPONSE_BYTES = 16 * 1024
        private const val MAX_MANIFEST_BYTES = 256 * 1024
    }
}
