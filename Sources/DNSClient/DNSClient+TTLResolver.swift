//
//  DNSClient+TTLResolver.swift
//
//
//  Created by Aviad Segev on 23/05/2024.
//

import NIO

public protocol TTLResolver {
    /// Initiate a DNS A query for a given host. Returns results with their time to live (TTL) in seconds.
    ///
    /// - parameters:
    ///     - host: The hostname to do an A lookup on.
    ///     - port: The port we'll be connecting to.
    /// - returns: An `EventLoopFuture` that fires with the result of the lookup.
    func initiateTTLAQuery(host: String, port: Int) -> EventLoopFuture<[(SocketAddress, Int)]>
    
    /// Initiate a DNS AAAA query for a given host.
    ///
    /// - parameters:
    ///     - host: The hostname to do an AAAA lookup on.  Returns results with their time to live (TTL) in seconds
    ///     - port: The port we'll be connecting to.
    /// - returns: An `EventLoopFuture` that fires with the result of the lookup.
    func initiateTTLAAAAQuery(host: String, port: Int) -> EventLoopFuture<[(SocketAddress, Int)]>
    
    /// Cancel all outstanding DNS queries.
    ///
    /// This method is called whenever queries that have not completed no longer have their
    /// results needed. The resolver should, if possible, abort any outstanding queries and
    /// clean up their state.
    ///
    /// This method is not guaranteed to terminate the outstanding queries.
    func cancelQueries()
}

extension DNSClient : TTLResolver {
    public func initiateTTLAQuery(host: String, port: Int) -> EventLoopFuture<[(SocketAddress, Int)]> {
        let result = self.sendQuery(forHost: host, type: .a)

        return result.map { message in
            return message.answers.compactMap { answer -> (SocketAddress, Int)? in
                guard case .a(let record) = answer,
                let socketAddress = try? record.resource.address.socketAddress(port: port) else {
                    return nil
                }

                return (socketAddress, Int(record.ttl))
            }
        }
    }
    
    public func initiateTTLAAAAQuery(host: String, port: Int) -> EventLoopFuture<[(SocketAddress, Int)]> {
        let result = self.sendQuery(forHost: host, type: .aaaa)

        return result.map { message in
            return message.answers.compactMap { answer -> (SocketAddress, Int)? in
                guard
                    case .aaaa(let record) = answer,
                    record.resource.address.count == 16
                else {
                    return nil
                }

                let address = record.resource.address
                
                let scopeID: UInt32 = 0 // More info about scope_id/zone_id https://tools.ietf.org/html/rfc6874#page-3
                let flowinfo: UInt32 = 0 // More info about flowinfo https://tools.ietf.org/html/rfc6437#page-4
                
                // Copy the 16 address bytes straight in; the union member name differs per libc.
                var ipv6 = in6_addr()
                withUnsafeMutableBytes(of: &ipv6) { dst in
                    address.withUnsafeBytes { src in dst.copyBytes(from: src.prefix(16)) }
                }
                #if canImport(Darwin)
                // Only the BSD/Darwin sockaddr carries sin6_len.
                let sockaddr = sockaddr_in6(sin6_len: numericCast(MemoryLayout<sockaddr_in6>.size), sin6_family: sa_family_t(AF_INET6), sin6_port: in_port_t(port), sin6_flowinfo: flowinfo, sin6_addr: ipv6, sin6_scope_id: scopeID)
                #else
                let sockaddr = sockaddr_in6(sin6_family: sa_family_t(AF_INET6), sin6_port: in_port_t(port), sin6_flowinfo: flowinfo, sin6_addr: ipv6, sin6_scope_id: scopeID)
                #endif

                return (SocketAddress(sockaddr, host: host), Int(record.ttl))
            }
        }
    }
}
