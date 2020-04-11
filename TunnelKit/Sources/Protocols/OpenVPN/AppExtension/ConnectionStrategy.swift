//
//  ConnectionStrategy.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 6/18/18.
//  Copyright (c) 2020 Davide De Rosa. All rights reserved.
//
//  https://github.com/passepartoutvpn
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//
//  This file incorporates work covered by the following copyright and
//  permission notice:
//
//      Copyright (c) 2018-Present Private Internet Access
//
//      Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

import Foundation
import NetworkExtension
import SwiftyBeaver

private let log = SwiftyBeaver.self

class ConnectionStrategy {
    struct Endpoint: CustomStringConvertible {
        let record: DNSRecord
        
        let proto: EndpointProtocol
        
        // MARK: CustomStringConvertible

        var description: String {
            return "\(record.address.maskedDescription):\(proto)"
        }
    }

    struct EndpointIndex {
        var recordIndex: Int
        
        var protocolIndex: Int
        
        mutating func advance(records: [DNSRecord], protos: [EndpointProtocol]) -> Bool {
            protocolIndex += 1
            guard protocolIndex < protos.count else {
                recordIndex += 1
                guard recordIndex < records.count else {
                    return false
                }
                protocolIndex = 0
                return true
            }
            return true
        }

        mutating func reset() {
            recordIndex = 0
            protocolIndex = 0
        }
    }

    private let hostname: String?

    private var resolvedRecords: [DNSRecord]

    private let endpointProtocols: [EndpointProtocol]
    
    private var currentEndpointIndex: EndpointIndex

    init(configuration: OpenVPNTunnelProvider.Configuration) {
        hostname = configuration.sessionConfiguration.hostname
        if let resolvedAddresses = configuration.resolvedAddresses, !resolvedAddresses.isEmpty {
            resolvedRecords = resolvedAddresses.map { DNSRecord(address: $0, isIPv6: false) }
        } else {
            guard hostname != nil else {
                fatalError("Either hostname or configuration.resolvedAddresses required")
            }
            resolvedRecords = []
        }

        guard var endpointProtocols = configuration.sessionConfiguration.endpointProtocols else {
            fatalError("No endpoints provided")
        }
        if configuration.sessionConfiguration.randomizeEndpoint ?? false {
            endpointProtocols.shuffle()
        }
        self.endpointProtocols = endpointProtocols
        
        currentEndpointIndex = EndpointIndex(recordIndex: 0, protocolIndex: 0)
        skipToValidEndpoint()
    }
    
    private func skipToValidEndpoint() {
        guard !resolvedRecords.isEmpty else {
            return
        }
        while !isCurrentEndpointValid() {
            guard tryNextEndpoint() else {
                return
            }
        }
    }

    @discardableResult
    func tryNextEndpoint() -> Bool {
        repeat {
            guard currentEndpointIndex.advance(records: resolvedRecords, protos: endpointProtocols) else {
                return false
            }
        } while !isCurrentEndpointValid()
        log.debug("Try next endpoint: \(currentEndpoint()!)")
        return true
    }
    
    func currentEndpoint() -> Endpoint? {
        guard currentEndpointIndex.recordIndex < resolvedRecords.count, currentEndpointIndex.protocolIndex < endpointProtocols.count else {
            return nil
        }
        let record = resolvedRecords[currentEndpointIndex.recordIndex]
        let proto = endpointProtocols[currentEndpointIndex.protocolIndex]
        return Endpoint(record: record, proto: proto)
    }

    private func isCurrentEndpointValid() -> Bool {
        guard let endpoint = currentEndpoint() else {
            return false
        }
        if endpoint.record.isIPv6 {
            return endpoint.proto.socketType != .udp4 && endpoint.proto.socketType != .tcp4
        } else {
            return endpoint.proto.socketType != .udp6 && endpoint.proto.socketType != .tcp6
        }
    }
    
    func createSocket(
        from provider: NEProvider,
        timeout: Int,
        queue: DispatchQueue,
        completionHandler: @escaping (GenericSocket?, Error?) -> Void) {

        if let endpoint = currentEndpoint() {
            log.debug("Pick available endpoint: \(endpoint)")
            let socket = provider.createSocket(to: endpoint)
            completionHandler(socket, nil)
            return
        }
        log.debug("No endpoints available, will resort to DNS resolution")

        guard let hostname = hostname else {
            log.error("DNS resolution unavailable: no hostname provided!")
            completionHandler(nil, OpenVPNTunnelProvider.ProviderError.dnsFailure)
            return
        }
        log.debug("DNS resolve hostname: \(hostname.maskedDescription)")
        DNSResolver.resolve(hostname, timeout: timeout, queue: queue) { (records, error) in
            if let records = records, !records.isEmpty {
                self.resolvedRecords = records
                self.currentEndpointIndex.reset()
                log.debug("DNS resolved addresses: \(records.map { $0.address })")
            } else {
                log.error("DNS resolution failed!")
            }
            
            // prepare initial endpoint
            self.skipToValidEndpoint()

            guard let targetEndpoint = self.currentEndpoint() else {
                log.error("No endpoints available")
                completionHandler(nil, OpenVPNTunnelProvider.ProviderError.dnsFailure)
                return
            }

            log.debug("Pick resolved endpoint: \(targetEndpoint)")
            let socket = provider.createSocket(to: targetEndpoint)
            completionHandler(socket, nil)
        }
    }
}

private extension NEProvider {
    func createSocket(to endpoint: ConnectionStrategy.Endpoint) -> GenericSocket {
        let ep = NWHostEndpoint(hostname: endpoint.record.address, port: "\(endpoint.proto.port)")
        switch endpoint.proto.socketType {
        case .udp, .udp4, .udp6:
            let impl = createUDPSession(to: ep, from: nil)
            return NEUDPSocket(impl: impl)
            
        case .tcp, .tcp4, .tcp6:
            let impl = createTCPConnection(to: ep, enableTLS: false, tlsParameters: nil, delegate: nil)
            return NETCPSocket(impl: impl)
        }
    }
}
