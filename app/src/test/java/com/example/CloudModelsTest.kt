package com.example

import com.example.data.remote.CloudCertificateRule
import com.example.data.remote.CloudDocIds
import com.example.data.remote.CloudScanRecord
import com.example.data.remote.CloudWhitelistedApp
import com.example.data.remote.UserSecurityProfile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudModelsTest {

  private val validIdRegex = Regex("^[a-zA-Z0-9_\\-]+$")

  @Test
  fun cloudDocIdsAlwaysMatchFirestoreRulesRegexAndMaxLength() {
    val longPkg = "com.very.long.package.name." + "segment.".repeat(25) + "app"
    val wlId = CloudDocIds.whitelistDocId(longPkg)
    assertTrue(wlId.length in 1..128)
    assertTrue(validIdRegex.matches(wlId))

    val certId = CloudDocIds.certRuleDocId("AA:BB:CC:DD:EE:FF:00:11:22:33")
    assertTrue(certId.length in 1..128)
    assertTrue(validIdRegex.matches(certId))

    val noSigCertId = CloudDocIds.certRuleDocId("SEM ASSINATURA")
    assertTrue(noSigCertId.length in 1..128)
    assertTrue(validIdRegex.matches(noSigCertId))

    val historyId = CloudDocIds.scanHistoryDocId("com.fake.trojan.app", 1_700_000_500_000L)
    assertTrue(historyId.length in 1..128)
    assertTrue(validIdRegex.matches(historyId))
  }

  @Test
  fun firestoreDataClassesProvideZeroArgDefaultsAndPreserveFields() {
    val profile = UserSecurityProfile()
    assertEquals("", profile.id)
    assertTrue(profile.autoSyncEnabled)

    val wl = CloudWhitelistedApp()
    assertEquals("", wl.id)
    assertEquals(0L, wl.addedAtMillis)

    val rule = CloudCertificateRule()
    assertEquals("", rule.id)
    assertEquals("TRUSTED", rule.trustStatus)

    val scan = CloudScanRecord()
    assertEquals("", scan.id)
    assertEquals(0L, scan.riskScore)
  }
}
