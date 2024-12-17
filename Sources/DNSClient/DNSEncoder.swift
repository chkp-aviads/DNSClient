import NIO

final class EnvelopeOutboundChannel: ChannelOutboundHandler {
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    
    let address: SocketAddress
    
    init(address: SocketAddress) {
        self.address = address
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = unwrapOutboundIn(data)
        let envelope = AddressedEnvelope(remoteAddress: address, data: buffer)
        context.write(wrapOutboundOut(envelope), promise: promise)
    }
}

final class UInt16FrameDecoder: ByteToMessageDecoder {
    typealias InboundOut = ByteBuffer
    
    func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        var readBuffer = buffer
        guard
            let size: UInt16 = readBuffer.readInteger(),
            let slice = readBuffer.readSlice(length: Int(size))
        else {
            return .needMoreData
        }
        
        buffer.moveReaderIndex(to: readBuffer.readerIndex)
        context.fireChannelRead(wrapInboundOut(slice))
        return .continue
    }
    
    func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        try decode(context: context, buffer: &buffer)
    }
}

final class UInt16FrameEncoder: MessageToByteEncoder {
    func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
        try out.writeLengthPrefixed(as: UInt16.self) { out in
            out.writeImmutableBuffer(data)
        }
    }
}

public final class DNSEncoder: ChannelOutboundHandler {
    public typealias OutboundIn = Message
    public typealias OutboundOut = ByteBuffer
    
    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let message = unwrapOutboundIn(data)
        do {
            let data = try DNSEncoder.encodeMessage(message, allocator: context.channel.allocator)
            context.write(wrapOutboundOut(data), promise: promise)
        } catch {
            promise?.fail(error)
        }
    }
    
    public static func encodeMessage(_ message: Message, allocator: ByteBufferAllocator) throws -> ByteBuffer {
        var out = allocator.buffer(capacity: 512)

        let header = message.header

        out.write(header)
        var labelIndices = [String : UInt16]()

        for question in message.questions {
            out.writeCompressedLabels(question.labels, labelIndices: &labelIndices)

            out.writeInteger(question.type.rawValue, endianness: .big)
            out.writeInteger(question.questionClass.rawValue, endianness: .big)
        }
        
        for answer in message.answers {
            try answer.write(to: &out)
        }

        return out
    }
}

extension Record {
    func write(to buffer: inout ByteBuffer) throws {
        switch self {
        case .aaaa(let resourceRecord):
            try resourceRecord.write(to: &buffer)
        case .a(let resourceRecord):
            try resourceRecord.write(to: &buffer)
        case .txt(let resourceRecord):
            try resourceRecord.write(to: &buffer)
        case .cname(let resourceRecord):
            try resourceRecord.write(to: &buffer)
        case .srv(let resourceRecord):
            try resourceRecord.write(to: &buffer)
        case .mx(let resourceRecord):
            try resourceRecord.write(to: &buffer)
        case .ptr(let resourceRecord):
            try resourceRecord.write(to: &buffer)
        case .other(let resourceRecord):
            try resourceRecord.write(to: &buffer)
        }
    }
}

extension ResourceRecord {
    func write(to out: inout ByteBuffer) throws {
        out.writeLabels(self.domainName)
        out.writeInteger(self.dataType, endianness: .big)
        out.writeInteger(self.dataClass, endianness: .big)
        out.writeInteger(self.ttl, endianness: .big)
        try self.resource.write(to: &out)
    }
}
