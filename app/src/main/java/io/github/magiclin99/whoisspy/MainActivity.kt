package io.github.magiclin99.whoisspy

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private val Danger = Color(0xFFD93036)
private val DangerBg = Color(0xFFFFEBEC)
private val Warn = Color(0xFFB86E00)
private val WarnBg = Color(0xFFFFF4E0)
private val Safe = Color(0xFF1B8A4B)
private val SafeBg = Color(0xFFE6F6EC)
private val Ink = Color(0xFF1F2A44)
private val Muted = Color(0xFF5B6478)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MaterialTheme(colorScheme = lightColorScheme(primary = Ink, background = Color(0xFFF7F7FA))) {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) { App() }
            }
        }
    }
}

private class Trusted(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("trusted", Context.MODE_PRIVATE)
    fun all(): Set<String> = prefs.getStringSet("pkgs", emptySet())!!.toSet()
    fun set(pkg: String, trusted: Boolean) {
        val s = all().toMutableSet().apply { if (trusted) add(pkg) else remove(pkg) }
        prefs.edit().putStringSet("pkgs", s).apply()
    }
}

@Composable
private fun App() {
    val ctx = LocalContext.current
    val trustedStore = remember { Trusted(ctx) }
    var result by remember { mutableStateOf<ScanResult?>(null) }
    var trusted by remember { mutableStateOf(trustedStore.all()) }
    var scanTick by remember { mutableIntStateOf(0) }

    // Rescan every time the user comes back from a settings screen, so fixed items disappear immediately.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { scanTick++ }
    LaunchedEffect(scanTick) {
        result = withContext(Dispatchers.Default) { Scanner.scan(ctx) }
    }

    val all = result?.findings
    val active = all?.filter { it.packageName !in trusted }.orEmpty()
    val danger = active.filter { it.level == Level.DANGER }
    val warn = active.filter { it.level == Level.WARNING }
    val sideloadedOnly = active.filter { it.level == Level.SIDELOADED }
    val trustedItems = all?.filter { it.packageName in trusted }.orEmpty()
    val onTrust: (Finding) -> Unit = { f -> trustedStore.set(f.packageName, true); trusted = trustedStore.all() }

    LazyColumn(
        modifier = Modifier.fillMaxSize().safeDrawingPadding(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text(stringResource(R.string.app_name), fontSize = 26.sp, fontWeight = FontWeight.Bold, color = Ink)
            Text(stringResource(R.string.tagline), color = Muted, fontSize = 14.sp)
        }
        item { Summary(all == null, danger.size, warn.size) }
        result?.device?.let { d ->
            if (d.vpnActive) item { DeviceBanner(R.string.device_vpn) { Fixes.openVpnSettings(ctx) } }
            if (d.adbEnabled) item { DeviceBanner(R.string.device_adb) { Fixes.openDeveloperSettings(ctx) } }
        }

        if (danger.isNotEmpty()) item { SectionTitle(stringResource(R.string.section_danger), Danger) }
        items(danger, key = { it.packageName }) { f -> FindingCard(f) { onTrust(f) } }
        if (warn.isNotEmpty()) item { SectionTitle(stringResource(R.string.section_warning), Warn) }
        items(warn, key = { it.packageName }) { f -> FindingCard(f) { onTrust(f) } }
        if (sideloadedOnly.isNotEmpty()) {
            item {
                SectionTitle(stringResource(R.string.section_sideloaded, sideloadedOnly.size), Ink)
                Text(stringResource(R.string.section_sideloaded_desc), color = Muted, fontSize = 12.sp)
            }
            items(sideloadedOnly, key = { it.packageName }) { f -> FindingCard(f) { onTrust(f) } }
        }

        if (trustedItems.isNotEmpty()) {
            item { SectionTitle(stringResource(R.string.section_trusted, trustedItems.size), Muted) }
            items(trustedItems, key = { "t:" + it.packageName }) { f ->
                TrustedRow(f) { trustedStore.set(f.packageName, false); trusted = trustedStore.all() }
            }
        }
        item { Tips() }
        item {
            Text(
                stringResource(R.string.privacy_policy), color = Muted, fontSize = 12.sp,
                modifier = Modifier.fillMaxWidth().clickable {
                    runCatching {
                        ctx.startActivity(
                            android.content.Intent(
                                android.content.Intent.ACTION_VIEW,
                                android.net.Uri.parse("https://magiclin99.github.io/whoisspy/privacy.html"),
                            ),
                        )
                    }
                }.padding(vertical = 12.dp),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            )
        }
    }
}

@Composable
private fun Summary(loading: Boolean, danger: Int, warn: Int) {
    val (bg, fg, title, body) = when {
        loading -> Quad(Color.White, Ink, stringResource(R.string.scanning), "")
        danger > 0 -> Quad(DangerBg, Danger, stringResource(R.string.summary_danger, danger), stringResource(R.string.summary_danger_body))
        warn > 0 -> Quad(WarnBg, Warn, stringResource(R.string.summary_warning, warn), stringResource(R.string.summary_warning_body))
        else -> Quad(SafeBg, Safe, stringResource(R.string.summary_safe), stringResource(R.string.summary_safe_body))
    }
    Column(
        Modifier.fillMaxWidth().background(bg, RoundedCornerShape(16.dp)).padding(18.dp),
    ) {
        if (loading) LinearProgressIndicator(Modifier.fillMaxWidth().padding(bottom = 8.dp))
        Text(title, color = fg, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        if (body.isNotEmpty()) Text(body, color = Ink, fontSize = 14.sp, modifier = Modifier.padding(top = 4.dp))
    }
}

private data class Quad(val a: Color, val b: Color, val c: String, val d: String)

@Composable
private fun SectionTitle(text: String, color: Color) =
    Text(text, color = color, fontWeight = FontWeight.Bold, fontSize = 15.sp, modifier = Modifier.padding(top = 8.dp))

@Composable
private fun AppIcon(f: Finding, size: Int = 44) {
    val bmp = remember(f.packageName) { f.icon?.let { runCatching { it.toBitmap(96, 96).asImageBitmap() }.getOrNull() } }
    if (bmp != null) Image(bmp, null, Modifier.size(size.dp))
    else Box(Modifier.size(size.dp).background(Color.LightGray, CircleShape))
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun FindingCard(f: Finding, onTrust: () -> Unit) {
    val ctx = LocalContext.current
    val accent = when (f.level) { Level.DANGER -> Danger; Level.WARNING -> Warn; else -> Muted }
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                AppIcon(f)
                Column(Modifier.padding(start = 12.dp).weight(1f)) {
                    Text(f.label, fontWeight = FontWeight.Bold, fontSize = 17.sp, color = Ink)
                    Text(f.packageName, fontSize = 11.sp, color = Muted)
                }
            }
            val tags = buildList {
                if (f.sideloaded) add(stringResource(R.string.tag_sideloaded))
                if (f.hiddenIcon) add(stringResource(R.string.tag_hidden))
                if (f.recentlyInstalled) add(stringResource(R.string.tag_recent))
                if (f.isSystem) add(stringResource(R.string.tag_system))
            }
            if (tags.isNotEmpty()) {
                FlowRow(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    tags.forEach { Tag(it, accent) }
                }
            }
            if (f.risks.isNotEmpty()) HorizontalDivider(Modifier.padding(vertical = 10.dp), color = Color(0xFFEDEEF2))
            f.risks.forEach { r -> RiskRow(r) { Fixes.revoke(ctx, f, r) } }

            if (Risk.DEVICE_ADMIN in f.risks) {
                Text(stringResource(R.string.admin_first), color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
            }
            Row(Modifier.padding(top = 10.dp).fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (!f.isSystem) {
                    Button(
                        onClick = { Fixes.uninstall(ctx, f.packageName) },
                        colors = ButtonDefaults.buttonColors(containerColor = Danger),
                        modifier = Modifier.weight(1f),
                    ) { Text(stringResource(R.string.action_uninstall)) }
                }
                OutlinedButton(onClick = onTrust, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.action_trust))
                }
            }
        }
    }
}

@Composable
private fun Tag(text: String, color: Color) =
    Text(
        text, color = color, fontSize = 11.sp, fontWeight = FontWeight.Medium,
        modifier = Modifier.background(color.copy(alpha = 0.1f), RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 3.dp),
    )

@Composable
private fun RiskRow(r: Risk, onFix: () -> Unit) {
    val (title, desc) = when (r) {
        Risk.ACCESSIBILITY -> R.string.risk_a11y to R.string.risk_a11y_desc
        Risk.SMS -> R.string.risk_sms to R.string.risk_sms_desc
        Risk.NOTIFICATIONS -> R.string.risk_notif to R.string.risk_notif_desc
        Risk.DEVICE_ADMIN -> R.string.risk_admin to R.string.risk_admin_desc
        Risk.OVERLAY -> R.string.risk_overlay to R.string.risk_overlay_desc
        Risk.INSTALL_APPS -> R.string.risk_install to R.string.risk_install_desc
        Risk.KEYBOARD -> R.string.risk_keyboard to R.string.risk_keyboard_desc
        Risk.CALLS -> R.string.risk_calls to R.string.risk_calls_desc
        Risk.VPN -> R.string.risk_vpn to R.string.risk_vpn_desc
        Risk.USAGE_ACCESS -> R.string.risk_usage to R.string.risk_usage_desc
    }
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f).padding(end = 8.dp)) {
            Text(stringResource(title), fontWeight = FontWeight.SemiBold, color = Ink, fontSize = 15.sp)
            Text(stringResource(desc), color = Muted, fontSize = 12.sp)
        }
        FilledTonalButton(onClick = onFix, contentPadding = PaddingValues(horizontal = 14.dp)) {
            Text(stringResource(R.string.action_revoke))
        }
    }
}

@Composable
private fun DeviceBanner(text: Int, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().background(WarnBg, RoundedCornerShape(12.dp)).padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(stringResource(text), Modifier.weight(1f).padding(end = 8.dp), color = Ink, fontSize = 13.sp)
        FilledTonalButton(onClick = onClick) { Text(stringResource(R.string.action_check)) }
    }
}

@Composable
private fun TrustedRow(f: Finding, onUntrust: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().background(Color.White, RoundedCornerShape(12.dp)).padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AppIcon(f, 32)
        Text(f.label, Modifier.weight(1f).padding(start = 10.dp), color = Ink)
        Text(
            stringResource(R.string.action_untrust), color = Danger, fontSize = 13.sp,
            modifier = Modifier.clickable(onClick = onUntrust).padding(6.dp),
        )
    }
}

@Composable
private fun Tips() {
    Column(
        Modifier.fillMaxWidth().padding(top = 12.dp).background(Color.White, RoundedCornerShape(16.dp)).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(stringResource(R.string.tips_title), fontWeight = FontWeight.Bold, color = Ink)
        listOf(R.string.tip_1, R.string.tip_2, R.string.tip_3, R.string.tip_4).forEach {
            Text("• " + stringResource(it), color = Muted, fontSize = 13.sp)
        }
    }
}
