package com.example.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

data class ServiceMonitorTelemetry(
  val isServiceRunning: Boolean = false,
  val lastSequenceNumber: Int = 0,
  val packagesVerifiedInSession: Int = 0,
  val lastVerifiedAppName: String? = null,
  val lastVerifiedVerdict: String? = null,
  val lastCheckTimestamp: Long = 0L,
)

object MonitorServiceState {
  private val _state = MutableStateFlow(ServiceMonitorTelemetry())
  val state: StateFlow<ServiceMonitorTelemetry> = _state.asStateFlow()

  fun markStarted(initialSequence: Int) {
    _state.update {
      it.copy(
        isServiceRunning = true,
        lastSequenceNumber = initialSequence,
        lastCheckTimestamp = System.currentTimeMillis(),
      )
    }
  }

  fun updateSequenceAndSweep(sequenceNumber: Int) {
    _state.update {
      it.copy(
        lastSequenceNumber = sequenceNumber,
        lastCheckTimestamp = System.currentTimeMillis(),
      )
    }
  }

  fun recordPackageVerified(appName: String, verdict: String) {
    _state.update {
      it.copy(
        packagesVerifiedInSession = it.packagesVerifiedInSession + 1,
        lastVerifiedAppName = appName,
        lastVerifiedVerdict = verdict,
        lastCheckTimestamp = System.currentTimeMillis(),
      )
    }
  }

  fun markStopped() {
    _state.update { it.copy(isServiceRunning = false) }
  }
}
