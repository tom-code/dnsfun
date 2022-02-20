

dgram = require('dgram');



class BParser {
    constructor(b) {
        this.buffer = b;
        this.ptr = 0;
    }
    getuint16() {
        var out = this.buffer.readUint16BE(this.ptr);
        this.ptr += 2;
        return out;
    }
    getuint8() {
        var out = this.buffer.readUInt8(this.ptr)
        this.ptr += 1;
        return out;
    }
    getbytes(n) {
        var out = this.buffer.subarray(this.ptr, this.ptr+n);
        this.ptr += n;
        return out;
    }
    remains() {
        return this.buffer.length - this.ptr;
    }
}

class BEncoder {
    constructor(s) {
        this.buffer = Buffer.alloc(s);
        this.ptr = 0;
    }
    putuint16(val) {
        var out = this.buffer.writeUint16BE(val, this.ptr);
        this.ptr += 2;
        return out;
    }
    putuint32(val) {
        var out = this.buffer.writeUint32BE(val, this.ptr);
        this.ptr += 4;
        return out;
    }
    putuint8(val) {
        var out = this.buffer.writeUInt8(val, this.ptr)
        this.ptr += 1;
        return out;
    }
    remains() {
        return this.buffer.length - this.ptr;
    }
    putbuffer(src) {
        src.copy(this.buffer, this.ptr, 0, src.length);
        this.ptr += src.length;
    }
    size() {
        return this.ptr;
    }
    export() {
        return this.buffer.slice(0, this.ptr);
    }
}


function parseName(parser) {
    var name = [];
    var a = [];
    while (parser.remains() > 2) {
        var size = parser.getuint8();
        if (size == 0) return name;
        var label = parser.getbytes(size);
        name.push(label);
    }
    return name;
}

function encName(encoder, name) {
    if (typeof name == 'string') {
        name = name.split('.');
    }
    for (label of name) {
        if (typeof(label) == 'string') {
            label = Buffer.from(label);
        }
        encoder.putuint8(label.length);
        encoder.putbuffer(label);
    }
    encoder.putuint8(0);
}

function nameToString(src) {
    out = '';
    var first = true;
    for (const label of src) {
        if (!first) out += '.';
        else first = false;
        out += label.toString('utf-8');
    }
    return out;
}


function decodeFlags(src) {
    var flags = {
        response: false
    };
    if (src & 0x8000) flags.response = true;
    flags.opcode = src>>11 & 0xf;
    return flags;
}

function encodeFlags(src) {
    flags = 0;
    if (('response' in src)  && src.response) flags |= 0x8000;
    if ('opcode' in src)    flags |= src.opcode << 11;
    if ('replyCode' in src) flags |= src.replyCode & 0xf;
    return flags;
}

function encodeData(e, src) {
    if (Array.isArray(src.data)) {
        var dbuf = Buffer.from(src.data);
        e.putuint16(dbuf.length);
        e.putbuffer(dbuf);
        return;
    }
    if (src.type == 33) {
        var ed = new BEncoder(1024);
        ed.putuint16(src.data.priority);
        ed.putuint16(src.data.weight);
        ed.putuint16(src.data.port);
        encName(ed, src.data.target);
        e.putuint16(ed.size());
        e.putbuffer(ed.export());
    }
}

function encode(p) {
    var e = new BEncoder(1024);
    e.putuint16(p.tid);
    if (typeof p.flags == 'number') {
        e.putuint16(p.flags);
    } else {
        e.putuint16(encodeFlags(p.flags))
    }
    e.putuint16(p.questions);
    e.putuint16(p.answerRRs);
    e.putuint16(p.authorityRRs);
    e.putuint16(p.additionalRRs);
    for (const query of p.queries) {
        encName(e, query.name);
        e.putuint16(query.type);
        e.putuint16(query.class);
    }
    for (const a of p.answers) {
        encName(e, a.name);
        e.putuint16(a.type);
        e.putuint16(a.class);
        e.putuint32(a.ttl);
        encodeData(e, a);
    }
    return e;
}

function encodeSRV(prio, weight, port, target) {
    var e = new BEncoder(1024);
    e.putuint16(prio);
    e.putuint16(weight);
    e.putuint16(port);
    encName(e, target);
    var o = e.buffer.slice(0, e.size());
    return Uint8Array.from(o);
}

function parse(buf) {
    var request = {};
    var parser = new BParser(buf);
    request.tid = parser.getuint16();
    request.flags = parser.getuint16();
    request.flagsDecoded = decodeFlags(request.flags);
    request.questions = parser.getuint16();
    request.answerRRs = parser.getuint16();
    request.authorityRRs = parser.getuint16();
    request.additionalRRs = parser.getuint16();
    request.queries = [];
    for (var i=0; i<request.questions; i++) {
        var query = {}
        query.name = parseName(parser);
        query.nameString = nameToString(query.name);
        query.type = parser.getuint16();
        query.class = parser.getuint16();
        request.queries.push(query);
    }
    request.createResponse = () => {
        return createResponse(request)
    };
    return request
}

function createResponse(src) {
    var resp = {
        tid: src.tid,
        flags: 0x8183,
        questions: src.questions,
        answerRRs: 0,
        authorityRRs: 0,
        additionalRRs: 0,
        queries: src.queries,
        answers: [],
        rinfo: src.rinfo
    };
    return resp;
}

class DnsServer {
    constructor() {
        this.servers = [];
    }

    bind(proto, port, block=true) {
        this.server = dgram.createSocket(proto);

        this.server.on('message', (msg, rinfo) => {
            try {
                var parsed = parse(msg);
                parsed.rinfo = rinfo;
            } catch (E) {
                return
            }
            //console.log(`incoming from ${rinfo.address}:${rinfo.port}`);
            if (this.msg_callback != null) {
                this.msg_callback(parsed);
            }
        });

        this.server.on('error', (err) => {
            //console.log(`server error:\n${err.stack}`);
            server.close();
        });

        this.server.on('listening', () => {
            const address = this.server.address();
            //console.log(`server listening ${address.address}:${address.port}`);
        });

        this.server.bind({port: port}, ()=> {
            //console.log("dodo");
        });

        if (!block) {
            this.server.unref();
        }
    }

    send(msg) {
        var encoded = encode(msg);
        this.server.send(encoded.buffer, 0, encoded.size(), msg.rinfo.port, msg.rinfo.address)
    }

    on_message(func) {
        this.msg_callback = func;
    }

    static Create() {
        return new DnsServer();
    }

    static createResponse(req) {
        return createResponse(req);
    }

    static TYPE = {
        A:     1,
        NS:    2,
        MD:    3,
        MF:    4,
        CNAME: 5,
        SOA:   6,
        AAAA:  28,
        SRV:   33
    }
    
    static CLASS = {
        IN:     1
    }

    static OPCODE = {
        QUERY : 0,
        IQUERY: 1,
        STATUS: 2
    }

    static RCODE = {
        NOERROR    :0,
        FORMERROR  :1,
        FAIL       :2,
        NAMEERROR  :3,
        NOTIMPL    :4,
        REFUSED    :5
    }
}

module.exports = DnsServer;