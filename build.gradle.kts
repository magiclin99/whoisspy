plugins {
    // AGP 9 has Kotlin support built in; only the Compose compiler plugin is added separately.
    id("com.android.application") version "9.5.2" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
}
