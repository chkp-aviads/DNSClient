import Testing
import NIO
@testable import DNSClient

#if canImport(Network)
import NIOTransportServices
#endif

struct DNSTCPClientTests {
    let group: MultiThreadedEventLoopGroup
    let dnsClient: DNSClient

    #if canImport(Network)
    let nwGroup: NIOTSEventLoopGroup
    let nwDnsClient: DNSClient
    #endif

    init() throws {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        dnsClient = try DNSClient.connectTCP(on: group, host: "8.8.8.8").wait()

        #if canImport(Network)
        nwGroup = NIOTSEventLoopGroup(loopCount: 1)
        nwDnsClient = try DNSClient.connectTSTCP(on: nwGroup, host: "8.8.8.8").wait()
        #endif
    }

    func testClient(_ perform: (DNSClient) throws -> Void) rethrows -> Void {
        try perform(dnsClient)
        #if canImport(Network)
        try perform(nwDnsClient)
        #endif
    }

    @Test
    func stringAddress() throws {
        var buffer = ByteBuffer()
        buffer.writeInteger(0x7F000001 as UInt32)
        let record = try #require(ARecord.read(from: &buffer, length: buffer.readableBytes))

        #expect(record.stringAddress == "127.0.0.1")
    }

    @Test
    func stringAddressAAAA() throws {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x2a, 0x00, 0x14, 0x50, 0x40, 0x01, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e] as [UInt8])

        let record = try #require(AAAARecord.read(from: &buffer, length: buffer.readableBytes))

        #expect(record.stringAddress == "2a00:1450:4001:0809:0000:0000:0000:200e")
    }

    @Test
    func aQuery() throws {
        try testClient { dnsClient in
            let results = try dnsClient.initiateAQuery(host: "google.com", port: 443).wait()
            #expect(results.count >= 1, "The returned result should be greater than or equal to 1")
        }
    }

    /// Test that we can resolve a domain name to an IPv6 address
    @Test
    func aaaaQuery() throws {
        try testClient { dnsClient in
            let results = try dnsClient.initiateAAAAQuery(host: "google.com", port: 443).wait()
            #expect(results.count >= 1, "The returned result should be greater than or equal to 1")
        }
    }

    /// Given a domain name, test that we can resolve it to an IPv4 address
    @Test
    func sendQueryA() throws {
        try testClient { dnsClient in
            let result = try dnsClient.sendQuery(forHost: "google.com", type: .a).wait()
            #expect(result.header.answerCount >= 1, "The returned answers should be greater than or equal to 1")
        }
    }

    /// Test that we can resolve example.com to an IPv6 address
    @Test
    func resolveExampleCom() throws {
        try testClient { dnsClient in
            let result = try dnsClient.sendQuery(forHost: "example.com", type: .aaaa).wait()
            #expect(result.header.answerCount >= 1, "The returned answers should be greater than or equal to 1")
        }
    }

    @Test
    func sendTxtQuery() throws {
        try testClient { dnsClient in
            let result = try dnsClient.sendQuery(forHost: "google.com", type: .txt).wait()
            #expect(result.header.answerCount >= 1, "The returned answers should be greater than or equal to 1")
        }
    }

    @Test
    func sendQueryMX() throws {
        try testClient { dnsClient in
            let result = try dnsClient.sendQuery(forHost: "gmail.com", type: .mx).wait()
            #expect(result.header.answerCount >= 1, "The returned answers should be greater than or equal to 1")
        }
    }

    @Test
    func sendQueryCNAME() throws {
        try testClient { dnsClient in
            let result = try dnsClient.sendQuery(forHost: "www.github.com", type: .cName).wait()
            #expect(result.header.answerCount >= 1, "The returned answers should be greater than or equal to 1")
        }
    }

    @Test
    func srvRecords() throws {
        try testClient { dnsClient in
            let answers = try dnsClient.getSRVRecords(from: "_caldavs._tcp.google.com").wait()
            #expect(answers.count >= 1, "The returned answers should be greater than or equal to 1")
        }
    }

    @Test
    func srvRecordsAsyncRequest() async throws {
        try await withTestClient { dnsClient in
            let answers = try await dnsClient.getSRVRecords(from: "_caldavs._tcp.google.com").get()
            #expect(answers.count >= 1, "The returned answers should be greater than or equal to 1")
        }
    }

    func withTestClient(_ perform: (DNSClient) async throws -> Void) async rethrows -> Void {
        try await perform(dnsClient)
        #if canImport(Network)
        try await perform(nwDnsClient)
        #endif
    }

    @Test
    func threadSafety() async throws {
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let client = try await DNSClient.connectTCP(
            on: eventLoopGroup.next(),
            host: "8.8.8.8"
        ).get()
        let hostname = "google.com"
        async let result = client.initiateAAAAQuery(host: hostname, port: 0).get()
        async let result2 = client.initiateAAAAQuery(host: hostname, port: 0).get()
        async let result3 = client.initiateAAAAQuery(host: hostname, port: 0).get()

        _ = try await [result, result2, result3]

        try await client.channel.close(mode: .all).get()
    }
}
