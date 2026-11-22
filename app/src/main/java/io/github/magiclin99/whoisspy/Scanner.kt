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
enum class Risk(val weight: Int) {
    ACCESSIBILITY(100), // reads the screen, taps and types: full remote control
    DEVICE_ADMIN(60),   // blocks uninstall, can lock / wipe
    SMS(50),            // reads OTP text messages
    NOTIFICATIONS(50),  // reads OTP shown in notifications
    KEYBOARD(45),       // third-party keyboard sees every OTP and password typed
    CALLS(40),          // call log / place calls / default dialer: call forwarding, fake bank callbacks
    OVERLAY(30),        // fake login page drawn over the bank app
    VPN(30),            // can intercept traffic
    USAGE_ACCESS(20),   // knows when you open the bank app (trigger for overlays)
    INSTALL_APPS(20),   // dropper: brings in more malware
}

enum class Level { DANGER, WARNING, SIDELOADED, OK }

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
        // Sideloaded + any capability is exactly what the current scam apps look like.
        sideloaded && risks.isNotEmpty() -> Level.DANGER
        Risk.ACCESSIBILITY in risks -> Level.DANGER
        risks.isNotEmpty() -> Level.WARNING
        sideloaded -> Level.SIDELOADED
        else -> Level.OK
    }
}

data class DeviceStatus(val vpnActive: Boolean, val adbEnabled: Boolean)

data class ScanResult(val findings: List<Finding>, val device: DeviceStatus)

object Scanner {

    /** App stores we treat as "reviewed source". Anything else (browser, file manager, chat app, adb) counts as sideloaded. */
    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending", "com.google.android.feedback",         // Google Play
        "com.sec.android.app.samsungapps",                             // Galaxy Store
        "com.huawei.appmarket",
        "com.xiaomi.market", "com.xiaomi.mipicks", "com.xiaomi.discover",
        "com.heytap.market", "com.oppo.market", "com.oplus.market",
        "com.bbk.appstore",                                            // vivo
        "com.amazon.venezia",
        "com.asus.appmarket",
        "com.google.android.packageinstaller.private.preinstalled",
    )

    /** OS components that legitimately hold "install unknown apps". */
    private val OS_INSTALLERS = setOf(
        "com.android.settings", "com.android.vending", "com.android.packageinstaller",
        "com.google.android.packageinstaller", "com.android.shell", "com.google.android.gms",
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

                // Pre-installed system apps (Find My Device, System Intelligence, Messages…) hold these
                // by default and malware cannot be a system app, so only third-party apps are judged.
                if (!isSystem) {
                    if (pkg in a11y) risks += Risk.ACCESSIBILITY
                    if (pkg in notif) risks += Risk.NOTIFICATIONS
                    if (pkg in admins) risks += Risk.DEVICE_ADMIN
                    if (pkg in keyboards) risks += Risk.KEYBOARD
                }
                // "Install unknown apps" is off by default for every app, so an explicit allow on a
                // pre-installed browser / chat app is the doorway malware came through.
                if (opMode(ctx, "android:request_install_packages", ai) == AppOpsManager.MODE_ALLOWED &&
                    (!isSystem || (updatedSystem && pkg in launchable && pkg !in OS_INSTALLERS))
                ) risks += Risk.INSTALL_APPS

                // Runtime permissions: pre-installed dialer / Messages legitimately hold these.
                if (!isSystem) {
                    if (granted(pm, pkg, Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS) || pkg == defaultSms)
                        risks += Risk.SMS
                    if (granted(pm, pkg, *CALL_PERMS.toTypedArray()) || pkg == defaultDialer) risks += Risk.CALLS
                    if (overlayAllowed(ctx, ai)) risks += Risk.OVERLAY
                    if (opMode(ctx, AppOpsManager.OPSTR_GET_USAGE_STATS, ai) == AppOpsManager.MODE_ALLOWED)
                        risks += Risk.USAGE_ACCESS
                }

                val installer = installerOf(pm, pkg)
                val sideloaded = !isSystem && installer !in TRUSTED_INSTALLERS
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

    private fun vpnActive(ctx: Context): Boolean = runCatching {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }.getOrDefault(false)

    private fun adbEnabled(ctx: Context): Boolean =
        Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
}
