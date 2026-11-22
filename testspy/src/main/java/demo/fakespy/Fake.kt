package demo.fakespy

import android.accessibilityservice.AccessibilityService
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.service.notification.NotificationListenerService
import android.view.accessibility.AccessibilityEvent

class Svc : AccessibilityService() {
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {}
    override fun onInterrupt() {}
}
class Notif : NotificationListenerService()
class Sms : BroadcastReceiver() { override fun onReceive(c: Context, i: Intent) {} }
