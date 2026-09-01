import Testing
import NIO
@testable import DNSClient

/// Offline tests for `SOARecord`. These need no name server, so they stay fast and deterministic.
@Suite("SOARecord")
struct SOARecordTests {

    private static func buffer(hex: String) -> ByteBuffer {
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return ByteBuffer(bytes: bytes)
    }

    /// A NODATA reply: NOERROR, no answers, and an SOA in the authority section. The SOA is what
    /// makes the negative answer cacheable, so it has to survive a full encode/decode round trip.
    @Test
    func roundTripsThroughEncoder() throws {
        let labels = [DNSLabel(stringLiteral: "google"),
                      DNSLabel(stringLiteral: "com"),
                      DNSLabel(stringLiteral: "")]
        let soa = SOARecord(
            domainName: "ns.google.com",
            adminMail: "hostmaster.google.com",
            serial: 1,
            refreshInterval: 3600,
            retryTimeinterval: 600,
            expireTimeout: 86400,
            minimumExpireTimeout: 300
        )
        let authority = Record.soa(ResourceRecord<SOARecord>(domainName: labels, dataType: DNSResourceType.soa.rawValue, dataClass: DataClass.internet.rawValue, ttl: 300, resource: soa))
        let header = DNSMessageHeader(id: 1234, options: .answer, questionCount: 1, answerCount: 0, authorityCount: 1, additionalRecordCount: 0)
        let question = QuestionSection(labels: labels, type: .aaaa, questionClass: .internet)
        let noDataResponse = Message(header: header, questions: [question], answers: [], authorities: [authority], additionalData: [])

        var labelIndices = [String: UInt16]()
        let payload = try DNSEncoder.encodeMessage(noDataResponse, allocator: ByteBufferAllocator(), labelIndices: &labelIndices)
        let decoded = try DNSDecoder.parse(payload)

        #expect(decoded.header.answerCount == 0)
        #expect(decoded.header.authorityCount == 1)
        guard case .soa(let record) = decoded.authorities[0] else {
            Issue.record("Authority should be an SOARecord, got \(decoded.authorities[0])")
            return
        }
        #expect(record.ttl == 300)
        #expect(record.resource.domainName.string == "ns.google.com")
        #expect(record.resource.adminMail.string == "hostmaster.google.com")
        #expect(record.resource.serial == 1)
        #expect(record.resource.refreshInterval == 3600)
        #expect(record.resource.retryTimeinterval == 600)
        #expect(record.resource.expireTimeout == 86400)
        #expect(record.resource.minimumExpireTimeout == 300)
    }

    /// Decodes bytes captured verbatim from 8.8.8.8 (a `www.youtube.com`/CNAME query, which is
    /// NODATA and so carries google.com's SOA in the authority section).
    ///
    /// This is the case the round-trip test above cannot reach. It decodes output from a real
    /// server rather than from our own encoder, so a bug mirrored in both `read` and `write` cannot
    /// hide; and the captured SOA uses **compression pointers** inside its RDATA (`c018`, `c031`
    /// for MNAME/RNAME), which our encoder deliberately never emits.
    @Test
    func decodesRealServerResponseWithCompressionPointers() throws {
        let response = Self.buffer(hex:
            "abcd818000010000000100000377777707796f757475626503636f6d0000050001" +
            "c010000600010000003c002d036e733106676f6f676c65c01809646e732d61646d" +
            "696ec0313a0aa9010000038400000384000007080000003c")

        let decoded = try DNSDecoder.parse(response)

        #expect(decoded.header.answerCount == 0)
        #expect(decoded.header.authorityCount == 1)
        guard case .soa(let record) = decoded.authorities[0] else {
            Issue.record("Authority should be an SOARecord, got \(decoded.authorities[0])")
            return
        }
        // Both names are pointer-compressed on the wire and must still resolve in full.
        #expect(record.resource.domainName.string == "ns1.google.com")
        #expect(record.resource.adminMail.string == "dns-admin.google.com")
        #expect(record.ttl == 60)
        #expect(record.resource.serial == 973_777_153)
        #expect(record.resource.refreshInterval == 900)
        #expect(record.resource.retryTimeinterval == 900)
        #expect(record.resource.expireTimeout == 1800)
        #expect(record.resource.minimumExpireTimeout == 60)
    }

    /// RDATA that stops part-way through the five fixed-width fields must fail rather than decode
    /// garbage — the names parse fine, so the guard has to catch the short read after them.
    @Test
    func rejectsTruncatedRData() throws {
        var encoded = ByteBuffer()
        var labelIndices = [String: UInt16]()
        let soa = SOARecord(
            domainName: "ns.example.com",
            adminMail: "hostmaster.example.com",
            serial: 1, refreshInterval: 2, retryTimeinterval: 3,
            expireTimeout: 4, minimumExpireTimeout: 5
        )
        let written = soa.write(into: &encoded, labelIndices: &labelIndices)

        // Drop the trailing `minimum` field: a well-formed prefix that is still too short.
        var truncated = try #require(encoded.getSlice(at: encoded.readerIndex, length: written - 4))
        #expect(SOARecord.read(from: &truncated, length: truncated.readableBytes) == nil)
    }

    /// The dotted-name convenience initializer is what callers synthesizing an SOA will use, so a
    /// fully-qualified name with a trailing dot must not produce a stray empty label.
    @Test
    func dottedNameInitializerIgnoresTrailingDot() throws {
        let soa = SOARecord(
            domainName: "ns.example.com.",
            adminMail: "hostmaster.example.com.",
            serial: 1, refreshInterval: 2, retryTimeinterval: 3,
            expireTimeout: 4, minimumExpireTimeout: 5
        )
        #expect(soa.domainName.count == 3)
        #expect(soa.domainName.string == "ns.example.com")
        #expect(soa.adminMail.string == "hostmaster.example.com")
    }
}
