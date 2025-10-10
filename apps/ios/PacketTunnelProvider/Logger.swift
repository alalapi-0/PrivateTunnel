//
//  Logger.swift
//  PacketTunnelProvider
//
//  Purpose: Lightweight logging wrapper to standardise log output from the
//  Network Extension components without pulling additional dependencies.
//
import Foundation
import os.log

enum Logger {
    private static let subsystem = "com.privatetunnel.PacketTunnelProvider"
    private static let generalLog = OSLog(subsystem: subsystem, category: "general")

    static func logInfo(_ message: String) {
        os_log("%{public}@", log: generalLog, type: .info, message)
    }

    static func logWarn(_ message: String) {
        os_log("%{public}@", log: generalLog, type: .default, message)
    }

    static func logError(_ message: String) {
        os_log("%{public}@", log: generalLog, type: .error, message)
    }
}
