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
                
                #if os(Linux)
                let ipAddress = address.withUnsafeBytes { buffer in
                    return buffer.bindMemory(to: in6_addr.__Unnamed_union___in6_u.self).baseAddress!.pointee
                }
                let sockaddr = sockaddr_in6(sin6_family: sa_family_t(AF_INET6), sin6_port: in_port_t(port), sin6_flowinfo: flowinfo, sin6_addr: in6_addr(__in6_u: ipAddress), sin6_scope_id: scopeID)
                #else
                let ipAddress = address.withUnsafeBytes { buffer in
                    return buffer.bindMemory(to: in6_addr.__Unnamed_union___u6_addr.self).baseAddress!.pointee
                }
                let size = MemoryLayout<sockaddr_in6>.size
                let sockaddr = sockaddr_in6(sin6_len: numericCast(size), sin6_family: sa_family_t(AF_INET6), sin6_port: in_port_t(port), sin6_flowinfo: flowinfo, sin6_addr: in6_addr(__u6_addr: ipAddress), sin6_scope_id: scopeID)
                #endif

                return (SocketAddress(sockaddr, host: host), Int(record.ttl))
            }
        }
    }
}
