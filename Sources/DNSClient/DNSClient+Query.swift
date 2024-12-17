import NIO
import NIOConcurrencyHelpers

extension DNSClient {
    /// Request A records
    ///
    /// - parameters:
    ///     - host: The hostname address to request the records from
    ///     - port: The port to use
    /// - returns: A future of SocketAddresses
    public func initiateAQuery(host: String, port: Int) -> EventLoopFuture<[SocketAddress]> {
        return initiateTTLAQuery(host: host, port: port).map { results in
            return results.map { $0.0 }
        }
    }

    /// Request AAAA records
    ///
    /// - parameters:
    ///     - host: The hostname address to request the records from
    ///     - port: The port to use
    /// - returns: A future of SocketAddresses
    public func initiateAAAAQuery(host: String, port: Int) -> EventLoopFuture<[SocketAddress]> {
        return initiateTTLAAAAQuery(host: host, port: port).map { results in
            return results.map { $0.0 }
        }
    }

    /// Cancel all queries that are currently running. This will fail all futures with a `CancelError`
    public func cancelQueries() {
        for (id, query) in dnsDecoder.messageCache {
            dnsDecoder.messageCache[id] = nil
            query.promise.fail(CancelError())
        }
    }

    /// Send a question to the dns host
    ///
    /// - parameters:
    ///     - address: The hostname address to request a certain resource from
    ///     - type: The resource you want to request
    ///     - additionalOptions: Additional message options
    /// - returns: A future with the response message
    public func sendQuery(forHost address: String, type: DNSResourceType, additionalOptions: MessageOptions? = nil) -> EventLoopFuture<Message> {
        channel.eventLoop.flatSubmit {
            let messageID = self.messageID.add(1)
            
            var options: MessageOptions = [.standardQuery]
            
            if !self.isMulticast {
                options.insert(.recursionDesired)
            }
            
            if let additionalOptions = additionalOptions {
                options.insert(additionalOptions)
            }
            
            let header = DNSMessageHeader(id: messageID, options: options, questionCount: 1, answerCount: 0, authorityCount: 0, additionalRecordCount: 0)
            let labels = address.split(separator: ".").map(String.init).map(DNSLabel.init)
            let question = QuestionSection(labels: labels, type: type, questionClass: .internet)
            let message = Message(header: header, questions: [question], answers: [], authorities: [], additionalData: [])
            
            return self.send(message)
        }
    }

    func send(_ message: Message, to address: SocketAddress? = nil) -> EventLoopFuture<Message> {
        let promise: EventLoopPromise<Message> = loop.makePromise()
        
        return loop.flatSubmit {
            self.dnsDecoder.messageCache[message.header.id] = SentQuery(message: message, promise: promise)
            self.channel.writeAndFlush(message, promise: nil)
            
            struct DNSTimeoutError: Error {}
            
            self.loop.scheduleTask(in: .seconds(Int64(self.ttl))) {
                promise.fail(DNSTimeoutError())
            }

            return promise.futureResult
        }
    }

    /// Request SRV records from a host
    ///
    /// - parameters:
    ///     - host: Hostname to get the records from
    /// - returns: A future with the resource record
    public func getSRVRecords(from host: String) -> EventLoopFuture<[ResourceRecord<SRVRecord>]> {
        return self.sendQuery(forHost: host, type: .srv).map { message in
            return message.answers.compactMap { answer in
                guard case .srv(let record) = answer else {
                    return nil
                }

                return record
            }
        }
    }
}
