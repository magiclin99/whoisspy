package io.github.magiclin99.whoisspy

import android.Manifest
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import android.telecom.TelecomManager
import android.view.accessibility.AccessibilityManager
import android.view.inputmethod.InputMethodManager

/** One dangerous capability an app currently holds. Weight ≈ how directly it enables OTP theft / account takeover. */
/** [stealsOtp]: can read an OTP or take over the phone on its own, as opposed to merely helping an attack. */
enum class Risk(val weight: Int, val stealsOtp: Boolean) {
    ACCESSIBILITY(100, true), // reads the screen, taps and types: full remote control
    DEVICE_ADMIN(60, true),   // blocks uninstall, can lock / wipe
    SMS(50, true),            // reads OTP text messages
    NOTIFICATIONS(50, true),  // reads OTP shown in notifications
    KEYBOARD(45, true),       // third-party keyboard sees every OTP and password typed
    CALLS(40, true),          // call log / place calls / default dialer: call forwarding, fake bank callbacks
    OVERLAY(30, true),        // fake login page drawn over the bank app
    VPN(30, false),           // can intercept traffic
    USAGE_ACCESS(20, false),  // knows when you open the bank app (trigger for overlays)
    INSTALL_APPS(20, false),  // dropper: brings in more malware
}

enum class Level { DANGER, WARNING, SIDELOADED, STORE_PERMS, OK }

data class Finding(
    val packageName: String,
    val label: String,
    val icon: Drawable?,
    val risks: List<Risk>,
    val sideloaded: Boolean,
    val installer: String?,
    val recentlyInstalled: Boolean,
    val hiddenIcon: Boolean,
    val isSystem: Boolean,
    val accessibilityComponent: ComponentName?,
    val notificationComponent: ComponentName?,
    val adminComponent: ComponentName?,
) {
    val score: Int = risks.sumOf { it.weight } * (if (sideloaded) 2 else 1) +
        (if (recentlyInstalled) 20 else 0) + (if (hiddenIcon) 40 else 0)

    val level: Level = when {
        // Sideloaded + a way to read OTPs is exactly what the current scam apps look like;
        // a sideloaded app hiding its icon has no innocent reason to hold anything.
        sideloaded && (risks.any { it.stealsOtp } || (hiddenIcon && risks.isNotEmpty())) -> Level.DANGER
        sideloaded && risks.isNotEmpty() -> Level.WARNING
        // Store apps routinely hold notification / overlay / keyboard rights (LINE, Gboard, Teams…),
        // so only remote control is worth interrupting the user for.
        Risk.ACCESSIBILITY in risks -> Level.WARNING
        sideloaded -> Level.SIDELOADED
        risks.isNotEmpty() -> Level.STORE_PERMS
        else -> Level.OK
    }
}

data class DeviceStatus(val vpnActive: Boolean, val adbEnabled: Boolean)

data class ScanResult(val findings: List<Finding>, val device: DeviceStatus)

object Scanner {

    /**
     * App stores we treat as "reviewed source". Anything else (browser, file manager, chat app, adb) counts as sideloaded.
     * A package name proves nothing by itself, so a store only counts when it is part of the firmware
     * or signed with a firmware key: see [scan].
     */
    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending", "com.google.android.feedback",         // Google Play
        "com.sec.android.app.samsungapps",                             // Galaxy Store
        "com.huawei.appmarket",
        "com.xiaomi.market", "com.xiaomi.mipicks", "com.xiaomi.discover",
        "com.heytap.market", "com.oppo.market", "com.oplus.market",
        "com.bbk.appstore", "com.vivo.appstore",
        "com.hihonor.appmarket",
        "com.transsnet.store",                                         // Tecno / Infinix / itel
        "com.amazon.venezia",
        "com.asus.appmarket",
        "com.android.chrome",                                          // WebAPKs minted by Google for PWAs
    )

    /** OS components that legitimately hold "install unknown apps". */
    private val OS_INSTALLERS = setOf(
        "com.android.settings", "com.android.vending", "com.android.packageinstaller",
        "com.google.android.packageinstaller", "com.android.shell", "com.google.android.gms",
    )

    /** What installs an APK the user tapped in a browser, chat app or file manager, or pushed over USB. */
    private val GENERIC_INSTALLERS = setOf(
        "com.google.android.packageinstaller", "com.android.packageinstaller",
        "com.samsung.android.packageinstaller", "com.miui.packageinstaller", "com.android.shell",
    )

    /**
     * SHA-256 of the AOSP sample signing keys (testkey, platform, shared, media, networkstack).
     * Their private halves are public, and some cheap ROMs ship signed with them, so on those phones
     * "signed like the firmware" proves nothing.
     */
    private val PUBLIC_TEST_CERTS = setOf(
        "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc",
        "c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8",
        "28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd",
        "465983f7791f2abeb43ea2cbdc7f21a8260b72bc08a55c839fc1a43bc741a81e",
        "e1dbadce60dc080d15b58a014b0dcf9400e24de23fa00b287a5a982bfebda2ee",
    )

    private const val RECENT_MS = 30L * 24 * 60 * 60 * 1000
    private val CALL_PERMS = listOf(
        Manifest.permission.READ_CALL_LOG, Manifest.permission.CALL_PHONE,
        Manifest.permission.ANSWER_PHONE_CALLS, @Suppress("DEPRECATION") Manifest.permission.PROCESS_OUTGOING_CALLS,
    )

    fun scan(ctx: Context): ScanResult {
        val pm = ctx.packageManager
        val self = ctx.packageName

        val a11y = enabledAccessibility(ctx)
        val notif = enabledComponents(ctx, "enabled_notification_listeners")
        val admins = (ctx.getSystemService(DevicePolicyManager::class.java)?.activeAdmins ?: emptyList())
            .associateBy { it.packageName }
        val defaultSms = runCatching { Telephony.Sms.getDefaultSmsPackage(ctx) }.getOrNull()
        val defaultDialer = runCatching { ctx.getSystemService(TelecomManager::class.java)?.defaultDialerPackage }.getOrNull()
        val keyboards = runCatching {
            ctx.getSystemService(InputMethodManager::class.java).enabledInputMethodList.map { it.packageName }.toSet()
        }.getOrDefault(emptySet())
        val vpnApps = pm.queryIntentServices(Intent(VpnService.SERVICE_INTERFACE), 0)
            .map { it.serviceInfo.packageName }.toSet()
        val launchable = pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
            .map { it.activityInfo.packageName }.toSet()

        val apps = runCatching { pm.getInstalledApplications(0) }.getOrDefault(emptyList())
        val firmwareCerts by lazy {
            apps.filter { it.flags and ApplicationInfo.FLAG_SYSTEM != 0 }.flatMap { certsOf(pm, it.packageName) }.toSet() -
                PUBLIC_TEST_CERTS
        }
        val vendorSigned = { pkg: String -> certsOf(pm, pkg).any { it in firmwareCerts } }
        val systemPkgs = apps.filter { it.flags and ApplicationInfo.FLAG_SYSTEM != 0 }.map { it.packageName }.toSet()
        // Anyone can name an app "com.android.vending"; only the real one is in the firmware or signed like it.
        val genuineStore = HashMap<String, Boolean>()
        val isGenuineStore = { inst: String ->
            genuineStore.getOrPut(inst) { inst in TRUSTED_INSTALLERS && (inst in systemPkgs || vendorSigned(inst)) }
        }
        val now = System.currentTimeMillis()

        val findings = apps.asSequence()
            .filter { it.packageName != self }
            .mapNotNull { ai ->
                val pkg = ai.packageName
                val isSystem = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
                // Pre-installed apps that get Play updates (Chrome, LINE, Facebook…) are the usual
                // doorway for sideloading; core OS components never get here.
                val updatedSystem = ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
                val risks = mutableListOf<Risk>()

                val installer = installerOf(pm, pkg)
                // Vendor apps delivered outside a store (Galaxy Wearable plugins, Samsung update center,
                // Smart Switch) carry the same signing key as the firmware's own apps; malware cannot.
                // That only holds when it also arrived through a vendor channel: vendor keys have leaked
                // before, and a scam APK always comes in through the generic installer.
                val vendorApp = !isSystem && !fromFile(pm, pkg) && installer != null &&
                    installer !in GENERIC_INSTALLERS && vendorSigned(pkg)
                val official = vendorApp || (!fromFile(pm, pkg) && installer != null && isGenuineStore(installer))
                val sideloaded = !isSystem && !official
                // The phone maker's own apps are judged like pre-installed ones, however they were delivered.
                val firmware = isSystem || vendorApp

                // Pre-installed system apps (Find My Device, System Intelligence, Messages…) hold these
                // by default and malware cannot be a system app, so only third-party apps are judged.
                if (!firmware) {
                    if (pkg in a11y) risks += Risk.ACCESSIBILITY
                    if (pkg in notif) risks += Risk.NOTIFICATIONS
                    if (pkg in admins) risks += Risk.DEVICE_ADMIN
                    if (pkg in keyboards) risks += Risk.KEYBOARD
                }
                // "Install unknown apps" is off by default for every app, so an explicit allow on a
                // pre-installed browser / chat app is the doorway malware came through.
                if (opMode(ctx, "android:request_install_packages", ai) == AppOpsManager.MODE_ALLOWED &&
                    (!firmware || ((updatedSystem || vendorApp) && pkg in launchable && pkg !in OS_INSTALLERS))
                ) risks += Risk.INSTALL_APPS

                // Runtime permissions: pre-installed dialer / Messages legitimately hold these.
                if (!firmware) {
                    if (granted(pm, pkg, Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS) || pkg == defaultSms)
                        risks += Risk.SMS
                    if (granted(pm, pkg, *CALL_PERMS.toTypedArray()) || pkg == defaultDialer) risks += Risk.CALLS
                    if (overlayAllowed(ctx, ai)) risks += Risk.OVERLAY
                    if (opMode(ctx, AppOpsManager.OPSTR_GET_USAGE_STATS, ai) == AppOpsManager.MODE_ALLOWED)
                        risks += Risk.USAGE_ACCESS
                }

                // VPN apps are normal from a store; a sideloaded one is not.
                if (pkg in vpnApps && sideloaded) risks += Risk.VPN

                if (risks.isEmpty() && !sideloaded) return@mapNotNull null

                val firstInstall = runCatching { pm.getPackageInfo(pkg, 0).firstInstallTime }.getOrDefault(0L)
                Finding(
                    packageName = pkg,
                    label = runCatching { ai.loadLabel(pm).toString() }.getOrDefault(pkg),
                    icon = runCatching { ai.loadIcon(pm) }.getOrNull(),
                    risks = risks.sortedByDescending { it.weight },
                    sideloaded = sideloaded,
                    installer = installer,
                    recentlyInstalled = !isSystem && now - firstInstall < RECENT_MS,
                    hiddenIcon = !isSystem && pkg !in launchable,
                    isSystem = isSystem,
                    accessibilityComponent = a11y[pkg],
                    notificationComponent = notif[pkg],
                    adminComponent = admins[pkg],
                )
            }
            .sortedWith(compareBy<Finding> { it.level.ordinal }.thenByDescending { it.score })
            .toList()

        return ScanResult(findings, DeviceStatus(vpnActive(ctx), adbEnabled(ctx)))
    }

    private fun certsOf(pm: PackageManager, pkg: String): List<String> = runCatching {
        val sigs = if (Build.VERSION.SDK_INT >= 28) {
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo ?: return@runCatching emptyList()
            if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
        } else {
            @Suppress("DEPRECATION") pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures
        }
        val md = java.security.MessageDigest.getInstance("SHA-256")
        sigs.orEmpty().map { sig -> md.digest(sig.toByteArray()).joinToString("") { "%02x".format(it) } }
    }.getOrDefault(emptyList())

    private fun granted(pm: PackageManager, pkg: String, vararg perms: String) =
        perms.any { pm.checkPermission(it, pkg) == PackageManager.PERMISSION_GRANTED }

    private fun enabledAccessibility(ctx: Context): Map<String, ComponentName> {
        val fromSettings = enabledComponents(ctx, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        val am = ctx.getSystemService(AccessibilityManager::class.java) ?: return fromSettings
        val fromManager = runCatching {
            am.getEnabledAccessibilityServiceList(android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .mapNotNull { it.resolveInfo?.serviceInfo }
                .associate { it.packageName to ComponentName(it.packageName, it.name) }
        }.getOrDefault(emptyMap())
        return fromSettings + fromManager
    }

    private fun enabledComponents(ctx: Context, key: String): Map<String, ComponentName> {
        val raw = runCatching { Settings.Secure.getString(ctx.contentResolver, key) }.getOrNull() ?: return emptyMap()
        return raw.split(':')
            .mapNotNull { ComponentName.unflattenFromString(it.trim()) }
            .associateBy { it.packageName }
    }

    private fun opMode(ctx: Context, op: String, ai: ApplicationInfo): Int {
        val ops = ctx.getSystemService(AppOpsManager::class.java) ?: return AppOpsManager.MODE_ERRORED
        return runCatching {
            if (Build.VERSION.SDK_INT >= 29) ops.unsafeCheckOpNoThrow(op, ai.uid, ai.packageName)
            else @Suppress("DEPRECATION") ops.checkOpNoThrow(op, ai.uid, ai.packageName)
        }.getOrDefault(AppOpsManager.MODE_ERRORED)
    }

    private fun overlayAllowed(ctx: Context, ai: ApplicationInfo): Boolean =
        when (opMode(ctx, AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, ai)) {
            AppOpsManager.MODE_ALLOWED -> true
            // MODE_DEFAULT falls back to the permission grant state.
            AppOpsManager.MODE_DEFAULT -> ctx.packageManager.checkPermission(
                Manifest.permission.SYSTEM_ALERT_WINDOW, ai.packageName,
            ) == PackageManager.PERMISSION_GRANTED
            else -> false
        }

    private fun installerOf(pm: PackageManager, pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
    }.getOrNull()

    /** Android 13+: the installer itself recorded that this came from an APK file. */
    private fun fromFile(pm: PackageManager, pkg: String): Boolean = Build.VERSION.SDK_INT >= 33 && runCatching {
        pm.getInstallSourceInfo(pkg).packageSource.let {
            it == android.content.pm.PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE ||
                it == android.content.pm.PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE
        }
    }.getOrDefault(false)

    private fun vpnActive(ctx: Context): Boolean = runCatching {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }.getOrDefault(false)

    private fun adbEnabled(ctx: Context): Boolean =
        Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
}
