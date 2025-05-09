import NIO
import Network
import NIOSSL
import Foundation

extension DNSClient {
    /// Connect to the dns server
    ///
    /// - parameters:
    ///     - group: EventLoops to use
    ///     - ttl: The interval in seconds that the network will use to for DNS TTL
    /// - returns: Future with the NioDNS client
    public static func connect(on group: EventLoopGroup, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        do {
            let configString = try String(contentsOfFile: "/etc/resolv.conf")
            let config = try ResolvConf(from: configString)

            return connect(on: group, config: config.nameservers)
        } catch {
            return group.next().makeFailedFuture(UnableToParseConfig())
        }
    }

    /// Connect to the dns server
    ///
    /// - parameters:
    ///     - group: EventLoops to use
    ///     - host: DNS host to connect to
    ///     - ttl: The interval in seconds that the network will use to for DNS TTL
    /// - returns: Future with the NioDNS client
    public static func connect(on group: EventLoopGroup, host: String, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        do {
            let address = try SocketAddress(ipAddress: host, port: 53)
            return connect(on: group, config: [address], ttl: ttl)
        } catch {
            return group.next().makeFailedFuture(error)
        }
    }
    
    /// Creates a multicast DNS client. This client will join the multicast group and listen for responses. It will also send queries to the multicast group.
    /// - parameters:
    ///    - group: EventLoops to use
    ///    -  ttl: The interval in seconds that the network will use to for DNS TTL
    public static func connectMulticast(on group: EventLoopGroup, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        do {
            let address = try SocketAddress(ipAddress: "224.0.0.251", port: 5353)
            
            return connect(on: group, config: [address], ttl: ttl).flatMap { client in
                let channel = client.channel as! MulticastChannel
                client.isMulticast = true
                return channel.joinGroup(address).map { client }
            }
        } catch {
            return group.next().makeFailedFuture(UnableToParseConfig())
        }
    }
    
    /// Connect to the dns server using TCP
    ///
    /// - parameters:
    ///     - group: EventLoops to use
    ///     - ttl: The interval in seconds that the network will use to for DNS TTL
    /// - returns: Future with the NioDNS client
    public static func connectTCP(on group: EventLoopGroup, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        do {
            let configString = try String(contentsOfFile: "/etc/resolv.conf")
            let config = try ResolvConf(from: configString)
            
            return connectTCP(on: group, config: config.nameservers, ttl: ttl)
        } catch {
            return group.next().makeFailedFuture(UnableToParseConfig())
        }
    }
    
    /// Connect to the dns server using TCP
    ///
    /// - parameters:
    ///     - group: EventLoops to use
    ///     - host: DNS host to connect to
    ///     -  ttl: The interval in seconds that the network will use to for DNS TTL
    /// - returns: Future with the NioDNS client
    public static func connectTCP(on group: EventLoopGroup, host: String, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        do {
            let address = try SocketAddress(ipAddress: host, port: 53)
            return connectTCP(on: group, config: [address], ttl: ttl)
        } catch {
            return group.next().makeFailedFuture(error)
        }
    }
    
    public static func connectDOT(on group: EventLoopGroup, host: String, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        do {
            let address = try SocketAddress.makeAddressResolvingHost(host, port: 853)
            let sslContext = try NIOSSLContext(configuration: .makeClientConfiguration())
            return connectTCP(on: group, config: [address], sslContext: sslContext, ttl: ttl)
        } catch {
            return group.next().makeFailedFuture(error)
        }
    }
    
    /// Set up the UDP channel to use the DNS protocol.
    /// - Parameters:
    ///   - channel: The UDP channel to use.
    ///   - context: A context containing the decoder and encoder to use.
    ///   - remoteAddress: The address to send the DNS requests to - based on NIO's AddressedEnvelope.
    /// - Returns: A future that will be completed when the channel is ready to use.
    public static func initializeChannel(_ channel: Channel, context: DNSClientContext, asEnvelopeTo remoteAddress: SocketAddress? = nil) -> EventLoopFuture<Void> {
        if let remoteAddress = remoteAddress {
            return channel.pipeline.addHandlers(
                EnvelopeInboundChannel(),
                context.decoder,
                EnvelopeOutboundChannel(address: remoteAddress),
                DNSEncoder()
            )
        } else {
            return channel.pipeline.addHandlers(context.decoder, DNSEncoder())
        }
    }

    /// Connect to the dns server and return a future with the client. This method will use UDP.
    /// - parameters:
    ///   - group: EventLoops to use
    ///  - config: DNS servers to connect to
    ///  - ttl: The interval in seconds that the network will use to for DNS TTL
    /// - returns: Future with the NioDNS client
    public static func connect(on group: EventLoopGroup, config: [SocketAddress], ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        guard let address = config.preferred else {
            return group.next().makeFailedFuture(MissingNameservers())
        }

        let dnsDecoder = DNSDecoder(group: group)

        let bootstrap = DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEPORT), value: 1)
            .channelInitializer { channel in
                return channel.pipeline.addHandlers(
                    EnvelopeInboundChannel(),
                    dnsDecoder,
                    EnvelopeOutboundChannel(address: address),
                    DNSEncoder()
                )
        }

		let ipv4 = address.protocol.rawValue == PF_INET
		
        return bootstrap.bind(host: ipv4 ? "0.0.0.0" : "::", port: 0).map { channel in
            let client = DNSClient(
                channel: channel,
                address: address,
                decoder: dnsDecoder,
                ttl: ttl
            )

            dnsDecoder.mainClient = client
            return client
        }
    }
    
    /// Connect to the dns server using TCP and return a future with the client.
    /// - parameters:
    ///    - group: EventLoops to use
    ///    - config: DNS servers to connect to
    ///    - ttl: The interval in seconds that the network will use to for DNS TTL
    /// - returns: Future with the NioDNS client
    public static func connectTCP(on group: EventLoopGroup, config: [SocketAddress], sslContext: NIOSSLContext? = nil, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        guard let address = config.preferred else {
            return group.next().makeFailedFuture(MissingNameservers())
        }
        
        let dnsDecoder = DNSDecoder(group: group)
        
        let bootstrap = ClientBootstrap(group: group)
            .channelInitializer { channel in
                return channel.eventLoop.submit {
                    if let sslContext {
                        return try channel.pipeline.syncOperations.addHandlers(
                            try! NIOSSLClientHandler(context: sslContext, serverHostname: nil),
                            ByteToMessageHandler(UInt16FrameDecoder()),
                            MessageToByteHandler(UInt16FrameEncoder()),
                            dnsDecoder,
                            DNSEncoder()
                        )
                    } else {
                        return try channel.pipeline.syncOperations.addHandlers(
                            ByteToMessageHandler(UInt16FrameDecoder()),
                            MessageToByteHandler(UInt16FrameEncoder()),
                            dnsDecoder,
                            DNSEncoder()
                        )
                    }
                }
            }
        
        return bootstrap.connect(to: address).map { channel in
            let client = DNSClient(
                channel: channel,
                address: address,
                decoder: dnsDecoder,
                ttl: ttl
            )
            
            dnsDecoder.mainClient = client
            return client
        }
    }
}

fileprivate extension Array where Element == SocketAddress {
    var preferred: SocketAddress? {
		return first(where: { $0.protocol.rawValue == PF_INET }) ?? first
    }
}

#if canImport(Network)
import NIOTransportServices

@available(iOS 12, *)
extension DNSClient {
    public static func connectTS(on group: NIOTSEventLoopGroup, host: String) -> EventLoopFuture<DNSClient> {
        do {
            let address = try SocketAddress(ipAddress: host, port: 53)
            return connectTS(on: group, config: [address])
        } catch {
            return group.next().makeFailedFuture(error)
        }
    }

    /// Connect to the dns server using TCP using NIOTransportServices. This is only available on iOS 12 and above.
    /// - parameters:
    ///   - group: EventLoops to use
    ///   - config: DNS servers to use
    ///   - ttl: The interval in seconds that the network will use to for DNS TTL
    /// - returns: Future with the NioDNS client. Use
    public static func connectTS(on group: NIOTSEventLoopGroup, config: [SocketAddress], ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        // Don't connect by UNIX domain socket. We currently don't intend to test & support that.
        guard
            let address = config.preferred,
            let ipAddress = address.ipAddress,
            let port = address.port
        else {
            return group.next().makeFailedFuture(MissingNameservers())
        }

        let dnsDecoder = DNSDecoder(group: group)
        
        return NIOTSDatagramBootstrap(group: group).channelInitializer { channel in
            return channel.pipeline.addHandlers(dnsDecoder, DNSEncoder())
        }
        .connect(host: ipAddress, port: port)
        .map { channel -> DNSClient in
            let client = DNSClient(
                channel: channel,
                address: address,
                decoder: dnsDecoder,
                ttl: ttl
            )

            dnsDecoder.mainClient = client
            return client
        }
    }

    /// Connect to the dns server using TCP using NIOTransportServices. This is only available on iOS 12 and above.
    /// The DNS Host is read from /etc/resolv.conf
    /// - parameters:
    ///   - group: EventLoops to use
    ///   - ttl: The interval in seconds that the network will use to for DNS TTL
    public static func connectTS(on group: NIOTSEventLoopGroup, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        do {
            let configString = try String(contentsOfFile: "/etc/resolv.conf")
            let config = try ResolvConf(from: configString)

            return connectTS(on: group, config: config.nameservers, ttl: ttl)
        } catch {
            return group.next().makeFailedFuture(UnableToParseConfig())
        }
    }

    public static func connectTSTCP(on group: NIOTSEventLoopGroup, host: String, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        do {
            let address = try SocketAddress(ipAddress: host, port: 53)
            return connectTSTCP(on: group, config: [address], tls: nil, ttl: ttl)
        } catch {
            return group.next().makeFailedFuture(error)
        }
    }
    
    public static func connectTSDOT(on group: NIOTSEventLoopGroup, host: String, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        do {
            let address = try SocketAddress.makeAddressResolvingHost(host, port: 853)
            let options = NWProtocolTLS.Options()
            return connectTSTCP(on: group, config: [address], tls: options, ttl: ttl)
        } catch {
            return group.next().makeFailedFuture(error)
        }
    }

    /// Connect to the dns server using TCP using NIOTransportServices. This is only available on iOS 12 and above.
    /// - parameters:
    ///   - group: EventLoops to use
    ///   - config: DNS servers to use
    ///   - ttl: The interval in seconds that the network will use to for DNS TTL
    /// - returns: Future with the NioDNS client. Use
    public static func connectTSTCP(on group: NIOTSEventLoopGroup, config: [SocketAddress], tls: NWProtocolTLS.Options? = nil, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        guard let address = config.preferred else {
            return group.next().makeFailedFuture(MissingNameservers())
        }

        let dnsDecoder = DNSDecoder(group: group)
        let tsBootstrap = NIOTSConnectionBootstrap(group: group)
        if let tls {
            _ = tsBootstrap.tlsOptions(tls)
        }
        return tsBootstrap .channelInitializer { channel in
            return channel.eventLoop.submit {
                return try channel.pipeline.syncOperations.addHandlers(
                    ByteToMessageHandler(UInt16FrameDecoder()),
                    MessageToByteHandler(UInt16FrameEncoder()),
                    dnsDecoder,
                    DNSEncoder()
                )
            }
        }
        .connect(to: address)
        .map { channel -> DNSClient in
            let client = DNSClient(
                channel: channel,
                address: address,
                decoder: dnsDecoder,
                ttl: ttl
            )

            dnsDecoder.mainClient = client
            return client
        }
    }
    
    /// Connect to the dns server using TCP using NIOTransportServices. This is only available on iOS 12 and above.
    /// The DNS Host is read from /etc/resolv.conf
    /// - parameters:
    ///   - group: EventLoops to use
    ///   - ttl: The interval in seconds that the network will use to for DNS TTL
    public static func connectTSTCP(on group: NIOTSEventLoopGroup, ttl: Int = 30) -> EventLoopFuture<DNSClient> {
        do {
            let configString = try String(contentsOfFile: "/etc/resolv.conf")
            let config = try ResolvConf(from: configString)

            return connectTSTCP(on: group, config: config.nameservers, tls: nil, ttl: ttl)
        } catch {
            return group.next().makeFailedFuture(UnableToParseConfig())
        }
    }
}
#endif
