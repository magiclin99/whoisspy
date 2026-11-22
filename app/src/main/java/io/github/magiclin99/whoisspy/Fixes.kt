package io.github.magiclin99.whoisspy

import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings

/**
 * Android never lets one app revoke another app's permissions, so every fix here
 * jumps the user straight to the exact system screen where the switch lives.
 */
object Fixes {

    fun revoke(ctx: Context, f: Finding, risk: Risk) {
        val pkgUri = Uri.parse("package:${f.packageName}")
        val candidates: List<Intent> = when (risk) {
            Risk.ACCESSIBILITY -> listOfNotNull(
                f.accessibilityComponent?.takeIf { Build.VERSION.SDK_INT >= 30 }?.let {
                    Intent("android.settings.ACCESSIBILITY_DETAILS_SETTINGS")
                        .putExtra(Intent.EXTRA_COMPONENT_NAME, it.flattenToString())
                },
                Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS),
            )
            Risk.NOTIFICATIONS -> listOfNotNull(
                f.notificationComponent?.takeIf { Build.VERSION.SDK_INT >= 30 }?.let {
                    Intent(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS)
                        .putExtra(Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME, it.flattenToString())
                },
                Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS),
            )
            Risk.DEVICE_ADMIN -> listOf(
                Intent().setComponent(ComponentName("com.android.settings", "com.android.settings.Settings\$DeviceAdminSettingsActivity")),
                Intent().setComponent(ComponentName("com.android.settings", "com.android.settings.DeviceAdminSettings")),
                Intent(Settings.ACTION_SECURITY_SETTINGS),
            )
            Risk.OVERLAY -> listOf(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, pkgUri))
            Risk.INSTALL_APPS -> listOf(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, pkgUri))
            Risk.SMS, Risk.CALLS -> listOf(appDetails(f.packageName), Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
            Risk.KEYBOARD -> listOf(Intent(Settings.ACTION_INPUT_METHOD_SETTINGS))
            Risk.VPN -> listOf(Intent(Settings.ACTION_VPN_SETTINGS))
            Risk.USAGE_ACCESS -> listOfNotNull(
                Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, pkgUri).takeIf { Build.VERSION.SDK_INT >= 29 },
                Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS),
            )
        }
        launchFirst(ctx, candidates + appDetails(f.packageName))
    }

    fun openVpnSettings(ctx: Context) = launchFirst(ctx, listOf(Intent(Settings.ACTION_VPN_SETTINGS)))

    fun openDeveloperSettings(ctx: Context) =
        launchFirst(ctx, listOf(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS), Intent(Settings.ACTION_SETTINGS)))

    fun openAppInfo(ctx: Context, pkg: String) = launchFirst(ctx, listOf(appDetails(pkg)))

    fun uninstall(ctx: Context, pkg: String) = launchFirst(
        ctx,
        listOf(Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")), appDetails(pkg)),
    )

    private fun appDetails(pkg: String) =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg"))

    private fun launchFirst(ctx: Context, intents: List<Intent>) {
        for (i in intents) {
            try {
                ctx.startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                return
            } catch (_: ActivityNotFoundException) {
            } catch (_: SecurityException) {
            }
        }
    }
}
