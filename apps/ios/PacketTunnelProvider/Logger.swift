//
//  Logger.swift
//  PacketTunnelProvider
//
//  Purpose: Lightweight logging wrapper to standardise log output from the
//  Network Extension components without pulling additional dependencies.
//
import Foundation
import os.log

enum LogEventCode: String {
    case eventHealthPass = "EVT_HEALTH_PASS"
    case eventHealthFail = "EVT_HEALTH_FAIL"
    case eventKillSwitchEngaged = "EVT_KILLSWITCH_ENGAGED"
    case eventKillSwitchReleased = "EVT_KILLSWITCH_RELEASED"
    case eventEngineReady = "EVT_ENGINE_READY"
    case eventEngineWaiting = "EVT_ENGINE_WAITING"
    case eventEngineReconnect = "EVT_ENGINE_RECONNECT"
    case engineStart = "EVT_ENGINE_START"
    case engineStop = "EVT_ENGINE_STOP"
    case eventHealthInit = "EVT_HEALTH_INIT"
    case errorPingTimeout = "ERR_PING_TIMEOUT"
    case errorEngineTransport = "ERR_ENGINE_TRANSPORT"
    case errorEngineProtocol = "ERR_ENGINE_PROTOCOL"
    case errorEngineConfig = "ERR_ENGINE_CONFIG"
    case errorHTTPSUnreachable = "ERR_HTTPS_UNREACHABLE"
    case errorDNSFailure = "ERR_DNS_FAILURE"
}

struct LogEventRecord: Codable {
    let timestamp: Date
    let code: String
    let message: String
}

enum Logger {
    private static let subsystem = "com.privatetunnel.PacketTunnelProvider"
    private static let generalLog = OSLog(subsystem: subsystem, category: "general")
    private static let eventQueue = DispatchQueue(label: "com.privatetunnel.logger", qos: .utility)
    private static var events: [LogEventRecord] = []
    private static let maxEvents = 50

    static func logInfo(_ message: String) {
        os_log("%{public}@", log: generalLog, type: .info, message)
    }

    static func logWarn(_ message: String) {
        os_log("%{public}@", log: generalLog, type: .default, message)
    }

    static func logError(_ message: String) {
        os_log("%{public}@", log: generalLog, type: .error, message)
    }

    static func logDebug(_ message: String) {
        os_log("%{public}@", log: generalLog, type: .debug, message)
    }

    static func record(code: LogEventCode, message: String) {
        let logType: OSLogType
        switch code {
        case .errorPingTimeout, .errorEngineTransport, .errorEngineProtocol, .errorEngineConfig, .errorHTTPSUnreachable, .errorDNSFailure:
            logType = .error
        case .eventHealthFail:
            logType = .default
        default:
            logType = .info
        }

        os_log("[%{public}@] %{public}@", log: generalLog, type: logType, code.rawValue, message)

        let record = LogEventRecord(timestamp: Date(), code: code.rawValue, message: message)
        eventQueue.async {
            events.append(record)
            if events.count > maxEvents {
                events.removeFirst(events.count - maxEvents)
            }
        }
    }

    static func recentEvents(limit: Int = 20) -> [LogEventRecord] {
        eventQueue.sync {
            Array(events.suffix(limit))
        }
    }
}
