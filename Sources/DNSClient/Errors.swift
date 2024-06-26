struct UnableToParseConfig: Error {}
struct MissingNameservers: Error {}
struct CancelError: Error {}
struct AuthorityNotFound: Error {}
struct ProtocolError: Error {}
struct UnknownQuery: Error {}
struct MessageError : Error {
    let header: DNSMessageHeader
    let innerError: Error
}
