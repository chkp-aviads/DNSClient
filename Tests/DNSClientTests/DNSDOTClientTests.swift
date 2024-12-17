//
//  DNSDOTClientTests.swift
//
//
//  Created by Aviad Segev on 19/05/2024.
//

import XCTest
import NIO
import NIOSSL
@testable import DNSClient

#if canImport(Network)
import NIOTransportServices
#endif

public extension Data {
    init?(base64urlEncoded input: String) {
        var base64 = input
        base64 = base64.replacingOccurrences(of: "-", with: "+")
        base64 = base64.replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 {
            base64 = base64.appending("=")
        }
        self.init(base64Encoded: base64)
    }

    func base64urlEncodedString() -> String {
        var result = self.base64EncodedString()
        result = result.replacingOccurrences(of: "+", with: "-")
        result = result.replacingOccurrences(of: "/", with: "_")
        result = result.replacingOccurrences(of: "=", with: "")
        return result
    }
}

final class DNSDOTClientTests: XCTestCase {
    var group: MultiThreadedEventLoopGroup!
    var dnsClient: DNSClient!
    
#if canImport(Network)
    var nwGroup: NIOTSEventLoopGroup!
    var nwDnsClient: DNSClient!
#endif
    
    override func setUpWithError() throws {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        dnsClient = try DNSClient.connectDOT(on: group, host: "dns.google").wait()
        
#if canImport(Network)
        nwGroup = NIOTSEventLoopGroup(loopCount: 1)
        nwDnsClient = try DNSClient.connectTSDOT(on: nwGroup, host: "dns.google").wait()
#endif
    }
    
    func testClient(_ perform: (DNSClient) throws -> Void) rethrows -> Void {
        try perform(dnsClient)
#if canImport(Network)
        try perform(nwDnsClient)
#endif
    }
    
    func testDoHARecordPostWireframe() async throws {
//        let base64 = Data(base64Encoded: "q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")!
//        let requestMessage = try! DNSDecoder.decode(buffer: ByteBuffer(data: base64))
        
        // Define the DNS message
        let header = DNSMessageHeader(id: 542, options: [.standardQuery, .recursionDesired], questionCount: 1, answerCount: 0, authorityCount: 0, additionalRecordCount: 0)
        let labels = ("www.topvpn.com".split(separator: ".").map(String.init) /*+ [""]*/).map(DNSLabel.init)
        let questions = [QuestionType.a].map { QuestionSection(labels: labels, type: $0, questionClass: .internet) }
        let requestMessage = Message(header: header, questions: questions, answers: [], authorities: [], additionalData: [])

        // Build the POST request
        let url = URL(string: "https://cloudflare-dns.com/dns-query")!  // "https://dns.google/dns-query")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        var labelIndices = [String: UInt16]()
        var byteBuffer = try DNSEncoder.encodeMessage(requestMessage, allocator: ByteBufferAllocator(), labelIndices: &labelIndices)
        request.httpBody = byteBuffer.readData(length: byteBuffer.readableBytes)

        // Send request
        let (data, response) = try await URLSession.shared.data(for: request)
        
        // Decode response and verify results
        let statusCode = (response as! HTTPURLResponse).statusCode
        XCTAssertEqual(statusCode, 200)
        let responseMessage = try DNSDecoder.parse(ByteBuffer(data: data))
        if case .a(let record) = responseMessage.answers.first {
            print(record.resource.stringAddress)
        }
        XCTAssertFalse(data.isEmpty, "Received data should not be empty")
    }
    
    func testDoHARecordGetWireframe() async throws {
        let base64 = Data(base64Encoded: "q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")!
        _ = try! DNSDecoder.parse(ByteBuffer(data: base64))
        let base64Address = "www.topvpn.com".data(using: .utf8)!.base64urlEncodedString()
        // Build the Get request
        let url = URL(string: "https://cloudflare-dns.com/dns-query?dns=\(base64Address)")!  // "https://dns.google/dns-query?dns=\(base64Address)&type=a")!
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.addValue("application/dns-message", forHTTPHeaderField: "Accept")

        // Send request
        let (data, response) = try await URLSession.shared.data(for: request)
        
        // Decode response and verify results
        let statusCode = (response as! HTTPURLResponse).statusCode
        XCTAssertEqual(statusCode, 200)
        let responseMessage = try DNSDecoder.parse(ByteBuffer(data: data))
        if case .a(let record) = responseMessage.answers.first {
            print(record.resource.stringAddress)
        }
        XCTAssertFalse(data.isEmpty, "Received data should not be empty")
    }
    
    func testStringAddress() throws {
        var buffer = ByteBuffer()
        buffer.writeInteger(0x7F000001 as UInt32)
        guard let record = ARecord.read(from: &buffer, length: buffer.readableBytes) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(record.stringAddress, "127.0.0.1")
    }
    
    func testStringAddressAAAA() throws {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x2a, 0x00, 0x14, 0x50, 0x40, 0x01, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e] as [UInt8])
        
        guard let record = AAAARecord.read(from: &buffer, length: buffer.readableBytes) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(record.stringAddress, "2a00:1450:4001:0809:0000:0000:0000:200e")
    }
    
    func testAQuery() throws {
        try testClient { dnsClient in
            let results = try dnsClient.initiateAQuery(host: "gmail.google.com", port: 443).wait()
            XCTAssertGreaterThanOrEqual(results.count, 1, "The returned result should be greater than or equal to 1")
        }
    }

    // Test that we can resolve a domain name to an IPv6 address
    func testAAAAQuery() throws {
        try testClient { dnsClient in
            let results = try dnsClient.initiateAAAAQuery(host: "google.com", port: 443).wait()
            XCTAssertGreaterThanOrEqual(results.count, 1, "The returned result should be greater than or equal to 1")
        }
    }

    // Given a domain name, test that we can resolve it to an IPv4 address
    func testSendQueryA() throws {
        try testClient { dnsClient in
            let result = try dnsClient.sendQuery(forHost: "gmail.google.com", type: .a).wait()
            XCTAssertGreaterThanOrEqual(result.header.answerCount, 1, "The returned answers should be greater than or equal to 1")
        }
    }

    // Test that we can resolve example.com to an IPv6 address
    func testResolveExampleCom() throws {
        try testClient { dnsClient in
            let result = try dnsClient.sendQuery(forHost: "example.com", type: .aaaa).wait()
            XCTAssertGreaterThanOrEqual(result.header.answerCount, 1, "The returned answers should be greater than or equal to 1")
        }
    }
    
    func testSendTxtQuery() throws {
        try testClient { dnsClient in
            let result = try dnsClient.sendQuery(forHost: "google.com", type: .txt).wait()
            XCTAssertGreaterThanOrEqual(result.header.answerCount, 1, "The returned answers should be greater than or equal to 1")
        }
    }
    
    func testSendQueryMX() throws {
        try testClient { dnsClient in
            let result = try dnsClient.sendQuery(forHost: "gmail.com", type: .mx).wait()
            XCTAssertGreaterThanOrEqual(result.header.answerCount, 1, "The returned answers should be greater than or equal to 1")
        }
    }

    func testSendQueryCNAME() throws {
        try testClient { dnsClient in
            let result = try dnsClient.sendQuery(forHost: "www.youtube.com", type: .cName).wait()
            XCTAssertGreaterThanOrEqual(result.header.answerCount, 1, "The returned answers should be greater than or equal to 1")
        }
    }

    func testSRVRecords() throws {
        try testClient { dnsClient in
            let answers = try dnsClient.getSRVRecords(from: "_caldavs._tcp.google.com").wait()
            XCTAssertGreaterThanOrEqual(answers.count, 1, "The returned answers should be greater than or equal to 1")
        }
    }
    
    func testSRVRecordsAsyncRequest() throws {
        testClient { dnsClient in
            let expectation = self.expectation(description: "getSRVRecords")
            
            dnsClient.getSRVRecords(from: "_caldavs._tcp.google.com")
                .whenComplete { (result) in
                    switch result {
                    case .failure(let error):
                        XCTFail("\(error)")
                    case .success(let answers):
                        XCTAssertGreaterThanOrEqual(answers.count, 1, "The returned answers should be greater than or equal to 1")
                    }
                    expectation.fulfill()
                }
            self.waitForExpectations(timeout: 5, handler: nil)
        }
    }
    
    func testThreadSafety() async throws {
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let client = try await DNSClient.connectDOT(
            on: eventLoopGroup.next(),
            host: "8.8.8.8"
        ).get()
        let hostname = "google.com"
        async let result = client.initiateAAAAQuery(host: hostname, port: 0).get()
        async let result2 = client.initiateAAAAQuery(host: hostname, port: 0).get()
        async let result3 = client.initiateAAAAQuery(host: hostname, port: 0).get()
        
        _ = try await [result, result2, result3]
        
        do {
            try await client.channel.close(mode: .all).get()
        } catch NIOSSLError.uncleanShutdown {
            // Nobody cares
        }
    }
    
    func testAll() throws {
        try testSRVRecords()
        try testSRVRecordsAsyncRequest()
        try testSendQueryMX()
        try testSendQueryCNAME()
        try testSendTxtQuery()
        try testAQuery()
        try testAAAAQuery()
    }
}
