import NIO

/// A DNS SOA record (RFC 1035 §3.3.13). This marks the start of a zone of authority.
///
/// Besides describing a zone, an SOA returned in the authority section of a negative answer is what
/// lets a resolver cache that negative result: RFC 2308 bounds the negative caching lifetime by
/// `min(SOA.minimumExpireTimeout, record TTL)`. A NODATA or NXDOMAIN reply without an SOA cannot be
/// cached at all, so clients re-ask for it every single time.
public struct SOARecord: DNSResource, Sendable {
    /// MNAME — the primary name server for the zone.
    public let domainName: [DNSLabel]

    /// RNAME — the mailbox of the person responsible for the zone, encoded as a domain name.
    public let adminMail: [DNSLabel]

    /// Version number of the zone file.
    public let serial: UInt32

    /// Seconds before the zone should be refreshed.
    public let refreshInterval: UInt32

    /// Seconds before a failed refresh should be retried.
    public let retryTimeinterval: UInt32

    /// Seconds before the zone is no longer authoritative.
    public let expireTimeout: UInt32

    /// Minimum TTL for any record in the zone. Per RFC 2308 this also bounds negative caching.
    public let minimumExpireTimeout: UInt32

    public init(
        domainName: [DNSLabel],
        adminMail: [DNSLabel],
        serial: UInt32,
        refreshInterval: UInt32,
        retryTimeinterval: UInt32,
        expireTimeout: UInt32,
        minimumExpireTimeout: UInt32
    ) {
        self.domainName = domainName
        self.adminMail = adminMail
        self.serial = serial
        self.refreshInterval = refreshInterval
        self.retryTimeinterval = retryTimeinterval
        self.expireTimeout = expireTimeout
        self.minimumExpireTimeout = minimumExpireTimeout
    }

    /// Convenience initializer taking dotted names, so callers synthesizing an SOA don't have to
    /// build `DNSLabel` arrays by hand.
    public init(
        domainName: String,
        adminMail: String,
        serial: UInt32,
        refreshInterval: UInt32,
        retryTimeinterval: UInt32,
        expireTimeout: UInt32,
        minimumExpireTimeout: UInt32
    ) {
        self.init(
            domainName: Self.labels(from: domainName),
            adminMail: Self.labels(from: adminMail),
            serial: serial,
            refreshInterval: refreshInterval,
            retryTimeinterval: retryTimeinterval,
            expireTimeout: expireTimeout,
            minimumExpireTimeout: minimumExpireTimeout
        )
    }

    /// Splits a dotted name into labels, dropping empty components so a trailing dot is harmless.
    /// Labels over 63 bytes are truncated rather than trapping `DNSLabel`'s length assertion.
    static func labels(from name: String) -> [DNSLabel] {
        name.split(separator: ".").map { component in
            DNSLabel(bytes: Array(component.utf8.prefix(63)))
        }
    }

    public static func read(from buffer: inout ByteBuffer, length: Int) -> SOARecord? {
        guard
            let domainName = buffer.readLabels(),
            let adminMail = buffer.readLabels(),
            let serial: UInt32 = buffer.readInteger(endianness: .big),
            let refreshInterval: UInt32 = buffer.readInteger(endianness: .big),
            let retryTimeinterval: UInt32 = buffer.readInteger(endianness: .big),
            let expireTimeout: UInt32 = buffer.readInteger(endianness: .big),
            let minimumExpireTimeout: UInt32 = buffer.readInteger(endianness: .big)
        else {
            return nil
        }

        return SOARecord(
            domainName: domainName,
            adminMail: adminMail,
            serial: serial,
            refreshInterval: refreshInterval,
            retryTimeinterval: retryTimeinterval,
            expireTimeout: expireTimeout,
            minimumExpireTimeout: minimumExpireTimeout
        )
    }

    public func write(into buffer: inout ByteBuffer, labelIndices: inout [String: UInt16]) -> Int {
        // MNAME/RNAME are written uncompressed. Compression pointers inside RDATA are legal per
        // RFC 1035 but are mishandled by enough stub resolvers to not be worth the handful of bytes,
        // especially since RDLENGTH already prefixes the section.
        var written = Self.writeName(domainName, into: &buffer)
        written += Self.writeName(adminMail, into: &buffer)
        written += buffer.writeInteger(serial, endianness: .big)
        written += buffer.writeInteger(refreshInterval, endianness: .big)
        written += buffer.writeInteger(retryTimeinterval, endianness: .big)
        written += buffer.writeInteger(expireTimeout, endianness: .big)
        written += buffer.writeInteger(minimumExpireTimeout, endianness: .big)
        return written
    }

    /// Writes a name as length-prefixed labels followed by the root terminator. Empty labels are
    /// skipped so an array that already carries a trailing `""` (as `readLabels()` produces) does
    /// not double-terminate.
    private static func writeName(_ labels: [DNSLabel], into buffer: inout ByteBuffer) -> Int {
        var written = 0
        for label in labels where label.length > 0 {
            written += buffer.writeInteger(label.length)
            written += buffer.writeBytes(label.label)
        }
        written += buffer.writeInteger(UInt8(0))
        return written
    }
}

extension SOARecord: CustomStringConvertible {
    public var description: String {
        "\(Self.self): \(domainName.string) \(adminMail.string) "
            + "(serial: \(serial), refresh: \(refreshInterval), retry: \(retryTimeinterval), "
            + "expire: \(expireTimeout), minimum: \(minimumExpireTimeout))"
    }
}
