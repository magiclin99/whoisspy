// Test-only fixture: a harmless app that holds the same capabilities as OTP-stealing malware,
// so "誰是間諜" can be verified on an emulator. Never published.
plugins { id("com.android.application") }
android {
    namespace = "demo.fakespy"
    compileSdk { version = release(37) { minorApiLevel = 2 } }
    defaultConfig { applicationId = "demo.fakespy"; minSdk = 26; targetSdk = 36; versionCode = 1; versionName = "1" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
