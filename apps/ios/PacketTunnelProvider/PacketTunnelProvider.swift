//
//  PacketTunnelProvider.swift
//  PacketTunnelProvider
//
//  Purpose: Entry point of the Network Extension. It reconstructs the WGConfig
//  passed by the container app, applies NEPacketTunnelNetworkSettings, and
//  launches the mock WireGuard engine to validate lifecycle flows.
//
import Foundation
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let providerConfigKey = "pt_config_json"
    private var engine: WGEngineMock?
    private var currentConfig: WGConfig?
    private var killSwitchEnabled = false

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        Logger.logInfo("PacketTunnelProvider.startTunnel invoked")

        guard let protocolConfiguration = protocolConfiguration as? NETunnelProviderProtocol else {
            Logger.logError("Protocol configuration is not NETunnelProviderProtocol")
            completionHandler(NSError(domain: "PacketTunnel", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid protocol configuration"]))
            return
        }

        guard let jsonString = protocolConfiguration.providerConfiguration?[providerConfigKey] as? String,
              let data = jsonString.data(using: .utf8) else {
            Logger.logError("Missing pt_config_json in providerConfiguration")
            completionHandler(NSError(domain: "PacketTunnel", code: -2, userInfo: [NSLocalizedDescriptionKey: "缺少配置数据"]))
            return
        }

        let config: WGConfig
        do {
            config = try WGConfigParser.parse(from: data)
            currentConfig = config
            killSwitchEnabled = config.enableKillSwitch
        } catch {
            Logger.logError("Failed to parse configuration: \(error.localizedDescription)")
            completionHandler(error)
            return
        }

        applyNetworkSettings(for: config) { [weak self] error in
            guard let self else { return }
            if let error {
                Logger.logError("Failed to apply network settings: \(error.localizedDescription)")
                completionHandler(error)
                return
            }

            let engine = WGEngineMock(packetFlow: self.packetFlow)
            engine.start(configuration: config)
            self.engine = engine

            Logger.logInfo("PacketTunnelProvider started successfully")
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        Logger.logInfo("PacketTunnelProvider.stopTunnel invoked. Reason: \(reason.rawValue)")
        engine?.stop()
        engine = nil
        currentConfig = nil

        // Placeholder: kill-switch strategy to be defined in later rounds.
        if killSwitchEnabled {
            Logger.logWarn("Kill switch requested but not yet implemented — traffic will follow system defaults.")
        }
        killSwitchEnabled = false
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        Logger.logInfo("Received app message of size \(messageData.count)")
        guard let handler = completionHandler else { return }

        var response: [String: Any] = [
            "status": connection.status.rawValue
        ]
        if let config = currentConfig {
            response["profile_name"] = config.profileName
        }

        let data = try? JSONSerialization.data(withJSONObject: response, options: [])
        handler(data)
    }

    private func applyNetworkSettings(for config: WGConfig, completion: @escaping (Error?) -> Void) {
        let remoteAddress = config.endpoint.host
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)

        let (address, mask) = parseAddress(config.client.address)
        let ipv4Settings = NEIPv4Settings(addresses: [address], subnetMasks: [mask])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        if config.routing.mode == .whitelist {
            Logger.logWarn("whitelist 模式暂未细化，临时使用默认全局路由。")
        }
        settings.ipv4Settings = ipv4Settings

        let dnsSettings = NEDNSSettings(servers: config.client.dns)
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings

        if let mtu = config.client.mtu {
            settings.mtu = NSNumber(value: mtu)
        }

        Logger.logInfo("Applying network settings: address=\(address) mask=\(mask) dns=\(config.client.dns)")

        setTunnelNetworkSettings(settings) { error in
            completion(error)
        }
    }

    private func parseAddress(_ cidr: String) -> (String, String) {
        let components = cidr.split(separator: "/")
        guard components.count == 2, let prefix = Int(components[1]) else {
            return (cidr, "255.255.255.255")
        }
        return (String(components[0]), subnetMask(from: prefix))
    }

    private func subnetMask(from prefixLength: Int) -> String {
        guard prefixLength >= 0 && prefixLength <= 32 else { return "255.255.255.255" }
        var mask: UInt32 = prefixLength == 0 ? 0 : ~UInt32(0) << (32 - UInt32(prefixLength))
        var octets: [String] = []
        for _ in 0..<4 {
            let value = (mask & 0xFF000000) >> 24
            octets.append(String(value))
            mask <<= 8
        }
        return octets.joined(separator: ".")
    }
}
