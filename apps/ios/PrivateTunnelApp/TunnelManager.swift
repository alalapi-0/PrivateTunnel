//
//  TunnelManager.swift
//  PrivateTunnel
//
//  Purpose: Bridges the container app UI with the Network Extension by managing the
//  lifecycle of NETunnelProviderManager and forwarding connect/disconnect requests.
//  The manager serialises TunnelConfig into providerConfiguration so the extension
//  can reconstruct WireGuard parameters when the tunnel starts.
//
//  Usage:
//      let tunnelManager = TunnelManager()
//      tunnelManager.save(configuration: config) { _ in }
//      tunnelManager.connect()
//
//  Notes:
//      - This file intentionally avoids singletons to keep dependency injection simple.
//      - All callbacks are delivered on the main thread for UI friendliness.
//
import Foundation
import NetworkExtension

final class TunnelManager: ObservableObject {
    enum TunnelError: LocalizedError {
        case configurationUnavailable
        case noConfigurationSelected
        case startFailed(Error)
        case stopFailed(Error)

        var errorDescription: String? {
            switch self {
            case .configurationUnavailable:
                return "无法加载或创建 VPN 配置。请检查 Network Extension 权限。"
            case .noConfigurationSelected:
                return "请先选择需要连接的配置。"
            case .startFailed(let error):
                return "启动隧道失败：\(error.localizedDescription)"
            case .stopFailed(let error):
                return "停止隧道失败：\(error.localizedDescription)"
            }
        }
    }

    @Published private(set) var currentStatus: NEVPNStatus = .invalid

    private let providerBundleIdentifier = "com.privatetunnel.PacketTunnelProvider"
    private let providerConfigKey = "pt_config_json"

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func loadOrCreateProvider(completion: @escaping (Result<NETunnelProviderManager, Error>) -> Void) {
        let bundleIdentifier = providerBundleIdentifier

        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            if let error {
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
                return
            }

            let existing = managers?.first(where: { manager in
                guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
                return proto.providerBundleIdentifier == bundleIdentifier
            })

            let targetManager: NETunnelProviderManager
            if let existing {
                targetManager = existing
            } else {
                let newManager = NETunnelProviderManager()
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = bundleIdentifier
                proto.serverAddress = "placeholder"
                newManager.protocolConfiguration = proto
                newManager.localizedDescription = "PrivateTunnel"
                newManager.isEnabled = true
                targetManager = newManager
            }

            self?.observeStatusUpdates(for: targetManager)
            self?.manager = targetManager

            DispatchQueue.main.async {
                completion(.success(targetManager))
            }
        }
    }

    func save(configuration: TunnelConfig, completion: @escaping (Result<Void, Error>) -> Void) {
        loadOrCreateProvider { [weak self] result in
            switch result {
            case .failure(let error):
                completion(.failure(error))
            case .success(let manager):
                guard let self else {
                    completion(.failure(TunnelError.configurationUnavailable))
                    return
                }

                let proto: NETunnelProviderProtocol
                if let existing = manager.protocolConfiguration as? NETunnelProviderProtocol {
                    proto = existing
                } else {
                    let newProto = NETunnelProviderProtocol()
                    newProto.providerBundleIdentifier = self.providerBundleIdentifier
                    proto = newProto
                }

                do {
                    let data = try JSONEncoder().encode(configuration)
                    guard let jsonString = String(data: data, encoding: .utf8) else {
                        throw TunnelError.configurationUnavailable
                    }
                    proto.providerBundleIdentifier = self.providerBundleIdentifier
                    proto.serverAddress = "\(configuration.endpoint.host):\(configuration.endpoint.port)"
                    var providerConfig = proto.providerConfiguration ?? [:]
                    providerConfig[self.providerConfigKey] = jsonString
                    proto.providerConfiguration = providerConfig
                    manager.protocolConfiguration = proto
                    manager.localizedDescription = configuration.profile_name
                    manager.isEnabled = true
                } catch {
                    completion(.failure(error))
                    return
                }

                manager.saveToPreferences { error in
                    guard error == nil else {
                        DispatchQueue.main.async {
                            completion(.failure(error!))
                        }
                        return
                    }

                    manager.loadFromPreferences { loadError in
                        DispatchQueue.main.async {
                            if let loadError {
                                completion(.failure(loadError))
                            } else {
                                completion(.success(()))
                            }
                        }
                    }
                }
            }
        }
    }

    func connect(completion: ((Result<Void, Error>) -> Void)? = nil) {
        loadOrCreateProvider { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                completion?(.failure(error))
            case .success(let manager):
                manager.loadFromPreferences { error in
                    if let error {
                        DispatchQueue.main.async {
                            completion?(.failure(error))
                        }
                        return
                    }

                    do {
                        try manager.connection.startVPNTunnel()
                        DispatchQueue.main.async {
                            completion?(.success(()))
                        }
                    } catch {
                        DispatchQueue.main.async {
                            completion?(.failure(TunnelError.startFailed(error)))
                        }
                    }
                }
            }
        }
    }

    func disconnect(completion: ((Result<Void, Error>) -> Void)? = nil) {
        if let manager {
            manager.connection.stopVPNTunnel()
            DispatchQueue.main.async {
                completion?(.success(()))
            }
        } else {
            loadOrCreateProvider { result in
                switch result {
                case .failure(let error):
                    completion?(.failure(error))
                case .success(let manager):
                    manager.connection.stopVPNTunnel()
                    DispatchQueue.main.async {
                        completion?(.success(()))
                    }
                }
            }
        }
    }

    func status() -> NEVPNStatus {
        manager?.connection.status ?? currentStatus
    }

    private func observeStatusUpdates(for manager: NETunnelProviderManager) {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            self?.currentStatus = manager.connection.status
        }
        currentStatus = manager.connection.status
    }
}
