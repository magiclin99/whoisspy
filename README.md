# 誰是間諜 Who's Spying

Android app that finds apps able to steal OTP codes (Accessibility, SMS, notification access, device admin, overlay, install-unknown-apps), flags sideloaded ones, and jumps straight to the system screen to revoke or uninstall.

- No internet permission, no data collection. See [privacy policy](https://magiclin99.github.io/whoisspy/privacy.html).
- No `QUERY_ALL_PACKAGES`: visibility comes from `<queries>` on the intents every OTP-stealer must declare.
- `testspy/` is a test-only fixture app that mimics malware capabilities for emulator verification. It is never published.

Build: `./gradlew :app:bundleRelease` (needs `keystore.properties`, not in git).
