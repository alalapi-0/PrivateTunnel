//
//  ContentView.swift
//  PrivateTunnel
//
//  Purpose: Presents the primary SwiftUI interface for importing, validating, and saving tunnel configurations.
//  Author: OpenAI Assistant
//  Created: 2024-05-15
//
//  Example:
//      ContentView()
//          .environmentObject(ConfigManager())
//
import SwiftUI

struct AlertDescriptor: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

struct ContentView: View {
    @EnvironmentObject private var configManager: ConfigManager

    @State private var isPresentingScanner = false
    @State private var isPresentingFileImporter = false
    @State private var importedConfig: TunnelConfig?
    @State private var alertDescriptor: AlertDescriptor?

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                Text("Private Tunnel Configurator")
                    .font(.title)
                    .fontWeight(.semibold)
                    .padding(.top, 8)

                if configManager.storedConfigs.isEmpty {
                    Text("尚未保存任何配置。通过下方按钮导入 JSON。")
                        .foregroundColor(.secondary)
                } else {
                    List {
                        Section(header: Text("已保存的配置")) {
                            ForEach(configManager.storedConfigs, id: \.profile_name) { config in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(config.profile_name)
                                        .font(.headline)
                                    Text("Endpoint: \(config.endpoint.host):\(config.endpoint.port)")
                                        .font(.subheadline)
                                    Text("Mode: \(config.routing.mode)")
                                        .font(.footnote)
                                        .foregroundColor(.secondary)
                                }
                                .padding(.vertical, 6)
                            }
                            .onDelete { indexSet in
                                indexSet.forEach { index in
                                    let config = configManager.storedConfigs[index]
                                    do {
                                        try configManager.delete(config: config)
                                    } catch {
                                        alertDescriptor = AlertDescriptor(title: "删除失败", message: error.localizedDescription)
                                    }
                                }
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                    .frame(maxHeight: 260)
                }

                if let importedConfig {
                    ConfigDetailView(config: importedConfig)

                    Button(action: {
                        do {
                            try configManager.save(config: importedConfig)
                            alertDescriptor = AlertDescriptor(title: "保存成功", message: "配置已保存，可在后续版本中启动隧道。")
                            self.importedConfig = nil
                        } catch {
                            alertDescriptor = AlertDescriptor(title: "保存失败", message: error.localizedDescription)
                        }
                    }) {
                        Text("保存配置")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                } else {
                    Text("导入配置后将在此处显示详情。")
                        .foregroundColor(.secondary)
                }

                Spacer()

                HStack {
                    Button(action: { isPresentingScanner = true }) {
                        Label("扫码导入 JSON", systemImage: "qrcode.viewfinder")
                    }
                    .buttonStyle(.bordered)

                    Button(action: { isPresentingFileImporter = true }) {
                        Label("从文件导入", systemImage: "folder")
                    }
                    .buttonStyle(.bordered)
                }
            }
            .padding()
            .sheet(isPresented: $isPresentingScanner) {
                QRScannerView { result in
                    isPresentingScanner = false
                    handleImportResult(result)
                }
            }
            .sheet(isPresented: $isPresentingFileImporter) {
                FileImporter { result in
                    isPresentingFileImporter = false
                    handleImportResult(result)
                }
            }
            .alert(item: $alertDescriptor) { descriptor in
                Alert(title: Text(descriptor.title), message: Text(descriptor.message), dismissButton: .default(Text("好的")))
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { configManager.reloadStoredConfigs() }) {
                        Label("刷新", systemImage: "arrow.clockwise")
                    }
                }
            }
        }
    }

    private func handleImportResult(_ result: Result<TunnelConfig, Error>) {
        switch result {
        case .success(let config):
            importedConfig = config
        case .failure(let error):
            alertDescriptor = AlertDescriptor(title: "解析失败", message: error.localizedDescription)
        }
    }
}

struct ConfigDetailView: View {
    let config: TunnelConfig

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("导入的配置")
                .font(.headline)
            Group {
                Text("Profile: \(config.profile_name)")
                Text("Endpoint: \(config.endpoint.host):\(config.endpoint.port)")
                Text("模式: \(config.routing.mode)")
                if let allowed = config.routing.allowed_ips, !allowed.isEmpty {
                    Text("AllowedIPs: \(allowed.joined(separator: ", "))")
                }
                if let whitelist = config.routing.whitelist_domains, !whitelist.isEmpty {
                    Text("Whitelist Domains: \(whitelist.joined(separator: ", "))")
                }
                Text("客户端地址: \(config.client.address)")
                Text("DNS: \(config.client.dns.joined(separator: ", "))")
            }
            .font(.subheadline)
            .foregroundColor(.primary)

            if let notes = config.notes, !notes.isEmpty {
                Text("备注: \(notes)")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(uiColor: .secondarySystemBackground))
        .cornerRadius(12)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
            .environmentObject(ConfigManager())
    }
}
