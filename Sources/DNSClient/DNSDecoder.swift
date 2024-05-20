import NIO

final class EnvelopeInboundChannel: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias InboundOut = ByteBuffer
    
    init() {}
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = unwrapInboundIn(data).data
        context.fireChannelRead(wrapInboundOut(buffer))
    }
}

final public class DNSDecoder: ChannelInboundHandler {
    let group: EventLoopGroup
    var messageCache = [UInt16: SentQuery]()
    var clients = [ObjectIdentifier: DNSClient]()
    weak var mainClient: DNSClient?

    init(group: EventLoopGroup) {
        self.group = group
    }

    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = Never
    
    public static func decode(buffer: ByteBuffer) throws -> Message {
        var buffer = buffer
        guard let header = buffer.readHeader() else {
            throw ProtocolError()
        }
        
        var questions = [QuestionSection]()
        
        for _ in 0..<header.questionCount {
            guard let question = buffer.readQuestion() else {
                throw MessageError(header: header, innerError: ProtocolError())
            }
            
            questions.append(question)
        }
        
        func resourceRecords(count: UInt16, header: DNSMessageHeader) throws -> [Record] {
            var records = [Record]()
            
            for _ in 0..<count {
                guard let record = buffer.readRecord() else {
                    throw MessageError(header: header, innerError: ProtocolError())
                }
                
                records.append(record)
            }
            
            return records
        }
        
        let answers = try resourceRecords(count: header.answerCount, header: header)
        let authorities = try resourceRecords(count: header.authorityCount, header: header)
        let additionalData = try resourceRecords(count: header.additionalRecordCount, header: header)
        
        return Message(
            header: header,
            questions: questions,
            answers: answers,
            authorities: authorities,
            additionalData: additionalData
        )
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = self.unwrapInboundIn(data)
        
        do {
            let message = try DNSDecoder.decode(buffer: envelope)
            
            if !message.header.options.contains(.answer) {
                return
            }

            guard let query = messageCache[message.header.id] else {
                return
            }

            query.promise.succeed(message)
            messageCache[message.header.id] = nil
        } catch let error {
            if let messageError = error as? MessageError {
                messageCache[messageError.header.id]?.promise.fail(messageError.innerError)
                messageCache[messageError.header.id] = nil
                context.fireErrorCaught(messageError.innerError)
            } else {
                context.fireErrorCaught(error)
            }
        }
    }

    public func errorCaught(context ctx: ChannelHandlerContext, error: Error) {
        for query in self.messageCache.values {
            query.promise.fail(error)
        }

        messageCache = [:]
    }
}
