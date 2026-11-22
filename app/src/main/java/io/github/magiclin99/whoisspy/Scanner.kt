package io.github.magiclin99.whoisspy

import android.Manifest
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import android.view.accessibility.AccessibilityManager

/** One dangerous capability an app currently holds. Ordered by how directly it enables OTP theft. */
enum class Risk(val weight: Int) {
    ACCESSIBILITY(100),   // can read the screen, tap buttons and type: full remote control
    DEVICE_ADMIN(60),     // blocks uninstall, can lock / wipe
    SMS(50),              // reads OTP text messages
    NOTIFICATIONS(50),    // reads OTP shown in notifications
    OVERLAY(30),          // draws fake login pages over bank apps
    INSTALL_APPS(20),     // can drop more malware
}

enum class Level { DANGER, WARNING, OK }

data class Finding(
    val packageName: String,
    val label: String,
    val icon: Drawable?,
    val risks: List<Risk>,
    val sideloaded: Boolean,
    val installer: String?,
    val recentlyInstalled: Boolean,
    val isSystem: Boolean,
    val accessibilityComponent: ComponentName?,
    val notificationComponent: ComponentName?,
    val adminComponent: ComponentName?,
) {
    val score: Int = risks.sumOf { it.weight } * (if (sideloaded) 2 else 1) + (if (recentlyInstalled) 20 else 0)

    val level: Level = when {
        // Sideloaded + any OTP-stealing capability is exactly what the current scam apps look like.
        sideloaded && risks.any { it != Risk.INSTALL_APPS } -> Level.DANGER
        Risk.ACCESSIBILITY in risks && !isSystem -> Level.DANGER
        risks.isNotEmpty() -> Level.WARNING
        else -> Level.OK
    }
}

object Scanner {

    /** App stores we treat as "reviewed source". Anything else (browser, file manager, chat app, adb) counts as sideloaded. */
    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending",            // Google Play
        "com.google.android.feedback",
        "com.sec.android.app.samsungapps", // Galaxy Store
        "com.huawei.appmarket",
        "com.xiaomi.market", "com.xiaomi.mipicks",
        "com.heytap.market", "com.oppo.market",
        "com.bbk.appstore",               // vivo
        "com.amazon.venezia",
        "com.asus.appmarket",
    )

    private const val RECENT_MS = 30L * 24 * 60 * 60 * 1000

    fun scan(ctx: Context): List<Finding> {
        val pm = ctx.packageManager
        val self = ctx.packageName

        val a11y = enabledAccessibility(ctx)
        val notif = enabledComponents(ctx, "enabled_notification_listeners")
        val admins = (ctx.getSystemService(DevicePolicyManager::class.java)?.activeAdmins ?: emptyList())
            .associateBy { it.packageName }
        val defaultSms = runCatching { Telephony.Sms.getDefaultSmsPackage(ctx) }.getOrNull()

        val apps = runCatching { pm.getInstalledApplications(0) }.getOrDefault(emptyList())
        val now = System.currentTimeMillis()

        return apps.asSequence()
            .filter { it.packageName != self }
            .mapNotNull { ai ->
                val pkg = ai.packageName
                val isSystem = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
                val risks = mutableListOf<Risk>()

                // Things the user had to switch on by hand: always report, even for system apps.
                if (pkg in a11y) risks += Risk.ACCESSIBILITY
                if (pkg in notif) risks += Risk.NOTIFICATIONS
                if (pkg in admins) risks += Risk.DEVICE_ADMIN

                // Runtime permissions: pre-installed system apps (dialer, Messages) legitimately hold these.
                if (!isSystem) {
                    val smsGranted = listOf(Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS)
                        .any { pm.checkPermission(it, pkg) == PackageManager.PERMISSION_GRANTED }
                    if (smsGranted && pkg != defaultSms) risks += Risk.SMS
                    if (opAllowed(ctx, AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, ai)) risks += Risk.OVERLAY
                    if (opAllowed(ctx, "android:request_install_packages", ai)) risks += Risk.INSTALL_APPS
                }

                if (risks.isEmpty()) return@mapNotNull null

                val installer = installerOf(pm, pkg)
                val firstInstall = runCatching { pm.getPackageInfo(pkg, 0).firstInstallTime }.getOrDefault(0L)
                Finding(
                    packageName = pkg,
                    label = runCatching { ai.loadLabel(pm).toString() }.getOrDefault(pkg),
                    icon = runCatching { ai.loadIcon(pm) }.getOrNull(),
                    risks = risks.sortedByDescending { it.weight },
                    sideloaded = !isSystem && installer !in TRUSTED_INSTALLERS,
                    installer = installer,
                    recentlyInstalled = !isSystem && now - firstInstall < RECENT_MS,
                    isSystem = isSystem,
                    accessibilityComponent = a11y[pkg],
                    notificationComponent = notif[pkg],
                    adminComponent = admins[pkg],
                )
            }
            .sortedWith(compareBy<Finding> { it.level.ordinal }.thenByDescending { it.score })
            .toList()
    }

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

    private fun opAllowed(ctx: Context, op: String, ai: ApplicationInfo): Boolean {
        val ops = ctx.getSystemService(AppOpsManager::class.java) ?: return false
        val mode = runCatching {
            if (Build.VERSION.SDK_INT >= 29) ops.unsafeCheckOpNoThrow(op, ai.uid, ai.packageName)
            else @Suppress("DEPRECATION") ops.checkOpNoThrow(op, ai.uid, ai.packageName)
        }.getOrDefault(AppOpsManager.MODE_ERRORED)
        // MODE_DEFAULT for overlay means "granted if the app declares the permission" on most builds.
        if (mode == AppOpsManager.MODE_ALLOWED) return true
        if (mode == AppOpsManager.MODE_DEFAULT && op == AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW) {
            return ctx.packageManager.checkPermission(Manifest.permission.SYSTEM_ALERT_WINDOW, ai.packageName) ==
                PackageManager.PERMISSION_GRANTED
        }
        return false
    }

    private fun installerOf(pm: PackageManager, pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
    }.getOrNull()
}
