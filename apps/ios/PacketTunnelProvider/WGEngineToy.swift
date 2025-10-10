//
//  WGEngineToy.swift
//  PacketTunnelProvider
//
//  Minimal UDP tunnel engine for development-only end-to-end testing. The engine
//  wraps IPv4 packets into a custom frame and ships them over UDP to a companion
//  Python gateway that bridges into a TUN device. There is no encryption or
//  authentication and the implementation is intentionally naive — it should
//  never be used outside of controlled lab environments.
//

import Foundation
import Network
import NetworkExtension
import Darwin

struct WGEngineToyStats: Codable {
    let packetsSent: UInt64
    let packetsReceived: UInt64
    let bytesSent: UInt64
    let bytesReceived: UInt64
    let lastActivity: Date
    let heartbeatsMissed: Int
}

enum ToyEngineError: Error {
    case connectionUnavailable
}

final class WGEngineToy {
    private let packetFlow: NEPacketTunnelFlow
    private let queue = DispatchQueue(label: "com.privatetunnel.toyengine", qos: .userInitiated)

    private var endpointHost: String = ""
    private var endpointPort: Int = 0
    private var connection: NWConnection?
    private var isRunning = false

    private var heartbeatTimer: DispatchSourceTimer?
    private var lastPong: Date = Date()
    private var missedHeartbeats: Int = 0

    private var packetsSent: UInt64 = 0
    private var packetsReceived: UInt64 = 0
    private var bytesSent: UInt64 = 0
    private var bytesReceived: UInt64 = 0
    private var lastActivity: Date = Date()

    init(packetFlow: NEPacketTunnelFlow) {
        self.packetFlow = packetFlow
    }

    func start(configuration: WGConfig) {
        queue.async { [weak self] in
            guard let self else { return }
            guard !self.isRunning else { return }
            self.endpointHost = configuration.endpoint.host
            self.endpointPort = configuration.endpoint.port
            self.isRunning = true
            self.packetsSent = 0
            self.packetsReceived = 0
            self.bytesSent = 0
            self.bytesReceived = 0
            self.lastActivity = Date()
            self.lastPong = Date()
            self.missedHeartbeats = 0

            Logger.logInfo("[ToyEngine] Starting. Endpoint=\(self.endpointHost):\(self.endpointPort)")
            self.setupConnection()
            self.schedulePacketFlowRead()
            self.startHeartbeat()
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            guard self.isRunning else { return }
            self.isRunning = false
            self.heartbeatTimer?.cancel()
            self.heartbeatTimer = nil
            self.connection?.cancel()
            self.connection = nil
            Logger.logInfo("[ToyEngine] Stopped. Sent=\(self.packetsSent) recv=\(self.packetsReceived)")
        }
    }

    func stats() -> WGEngineToyStats {
        queue.sync {
            WGEngineToyStats(
                packetsSent: packetsSent,
                packetsReceived: packetsReceived,
                bytesSent: bytesSent,
                bytesReceived: bytesReceived,
                lastActivity: lastActivity,
                heartbeatsMissed: missedHeartbeats
            )
        }
    }

    private func setupConnection() {
        let params = NWParameters.udp
        guard endpointPort > 0 && endpointPort < 65536 else {
            Logger.logError("[ToyEngine] Endpoint port out of range: \(endpointPort)")
            return
        }
        let portValue = UInt16(endpointPort)
        let endpoint = NWEndpoint.Host(endpointHost)
        guard let nwPort = NWEndpoint.Port(rawValue: portValue) else {
            Logger.logError("[ToyEngine] Invalid endpoint port: \(endpointPort)")
            return
        }

        let connection = NWConnection(host: endpoint, port: nwPort, using: params)
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                Logger.logInfo("[ToyEngine] UDP connection ready")
                self.queue.async {
                    self.scheduleReceive()
                }
            case .failed(let error):
                Logger.logError("[ToyEngine] Connection failed: \(error.localizedDescription)")
                self.handleConnectionFailure()
            case .waiting(let error):
                Logger.logWarn("[ToyEngine] Connection waiting: \(error.localizedDescription)")
            case .cancelled:
                Logger.logInfo("[ToyEngine] Connection cancelled")
            default:
                break
            }
        }

        connection.start(queue: queue)
        self.connection = connection
    }

    private func handleConnectionFailure() {
        guard isRunning else { return }
        Logger.logWarn("[ToyEngine] Attempting reconnection in 3 seconds")
        missedHeartbeats = 0
        lastPong = Date()
        queue.asyncAfter(deadline: .now() + .seconds(3)) { [weak self] in
            guard let self else { return }
            guard self.isRunning else { return }
            self.connection?.cancel()
            self.connection = nil
            self.setupConnection()
        }
    }

    private func schedulePacketFlowRead() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.queue.async {
                guard self.isRunning else { return }
                if packets.isEmpty {
                    self.schedulePacketFlowRead()
                    return
                }

                for (packet, proto) in zip(packets, protocols) {
                    guard proto.intValue == AF_INET else {
                        Logger.logDebug("[ToyEngine] Dropping non-IPv4 packet (proto=\(proto))")
                        continue
                    }
                    do {
                        try self.sendFrame(type: .dataIP, payload: packet)
                    } catch {
                        Logger.logError("[ToyEngine] Failed to send packet: \(error.localizedDescription)")
                    }
                }

                self.schedulePacketFlowRead()
            }
        }
    }

    private func scheduleReceive() {
        connection?.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            self.queue.async {
                guard self.isRunning else { return }
                if let error {
                    Logger.logError("[ToyEngine] Receive failed: \(error.localizedDescription)")
                    self.handleConnectionFailure()
                    return
                }

                guard let data else {
                    self.scheduleReceive()
                    return
                }

                do {
                    let frame = try TunnelProtocol.parseFrame(data)
                    try self.process(frame: frame)
                } catch {
                    Logger.logError("[ToyEngine] Failed to parse frame: \(error.localizedDescription)")
                }

                self.scheduleReceive()
            }
        }
    }

    private func sendFrame(type: TunnelFrameType, payload: Data) throws {
        guard let connection else {
            throw ToyEngineError.connectionUnavailable
        }

        let frame = try TunnelProtocol.encodeFrame(type: type, payload: payload)
        connection.send(content: frame, completion: .contentProcessed { error in
            if let error {
                Logger.logError("[ToyEngine] UDP send failed: \(error.localizedDescription)")
            }
        })

        if type == .dataIP {
            packetsSent += 1
            bytesSent += UInt64(payload.count)
        }
        lastActivity = Date()
    }

    private func process(frame: TunnelFrame) throws {
        switch frame.type {
        case .dataIP:
            guard !frame.payload.isEmpty else {
                return
            }
            packetsReceived += 1
            bytesReceived += UInt64(frame.payload.count)
            lastActivity = Date()
            packetFlow.writePackets([frame.payload], withProtocols: [NSNumber(value: AF_INET)])
        case .ping:
            Logger.logDebug("[ToyEngine] Received ping, replying with pong")
            lastActivity = Date()
            try sendFrame(type: .pong, payload: Data())
        case .pong:
            Logger.logDebug("[ToyEngine] Received pong")
            missedHeartbeats = 0
            lastPong = Date()
            lastActivity = Date()
        }
    }

    private func startHeartbeat() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(10), repeating: .seconds(10))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            guard self.isRunning else { return }

            do {
                try self.sendFrame(type: .ping, payload: Data())
            } catch {
                Logger.logError("[ToyEngine] Heartbeat send failed: \(error.localizedDescription)")
            }

            self.missedHeartbeats += 1
            if self.missedHeartbeats >= 3 {
                Logger.logWarn("[ToyEngine] Missed \(self.missedHeartbeats) heartbeats, forcing reconnect")
                self.missedHeartbeats = 0
                self.lastPong = Date()
                self.connection?.cancel()
                self.connection = nil
                self.setupConnection()
            }
        }
        timer.resume()
        heartbeatTimer = timer
    }
}
