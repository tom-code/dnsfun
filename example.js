dns = require('dnsfun')

var server = dns.Create();
server.on_message((request) => {
    console.log(request);
    var response = request.createResponse();
    if (request.flagsDecoded.opcode != dns.OPCODE.QUERY) {
        response.flags = {response: true, opcode: request.flagsDecoded.opcode, replyCode: dns.RCODE.NOTIMPL};
        server.send(resp);
        return;
    }

    response.answers = [];
    // respond with 127.0.0.1 to all A queries
    for (const query of request.queries) {
        if ((query.type == dns.TYPE.A) && (query.class == dns.CLASS.IN)) {
            response.answers.push({name: query.name, type: dns.TYPE.A, class: dns.CLASS.IN, ttl: 3600, data: [127, 0, 0, 1]});
        }
    }

    // add aaaa record
    response.answers.push({name: "v6.fun", type: dns.TYPE.AAAA, class: dns.CLASS.IN, ttl: 3600, data: [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]});

    // add some srv record to response
    const srv = {priority: 1, weight: 3, port: 1212, target: "x.y.z"}
    response.answers.push({name: "_svc._proto.name", type: dns.TYPE.SRV, class: dns.CLASS.IN, ttl: 3600, data: srv});

    // cname
    response.answers.push({name: "abc", type: dns.TYPE.CNAME, class: dns.CLASS.IN, ttl: 3600, data: dns.encodeName("x.e.z")});

    // cname2
    response.answers.push({name: "bbb", type: dns.TYPE.CNAME, class: dns.CLASS.IN, ttl: 3600, data: {cname: 'o.i.tt'}});

    // NS
    response.answers.push({name: "ccc", type: dns.TYPE.NS, class: dns.CLASS.IN, ttl: 3600, data: dns.encodeName("x.e.o")});

    // MX
    response.answers.push({name: "ddd", type: dns.TYPE.MX, class: dns.CLASS.IN, ttl: 3600, data: {preference: 1, exchange: "a.a.a"}});

    // SOA
    const soa = {mname: "a1.a2", rname: "a1.a3", serial: 100, refresh: 101, retry: 102, expire: 103, minimum: 104};
    response.answers.push({name: "ccc", type: dns.TYPE.SOA, class: dns.CLASS.IN, ttl: 3600, data: soa});

    // add a record into additional section
    response.additional.push({name: "a1.fun", type: dns.TYPE.A, class: dns.CLASS.IN, ttl: 3600, data: [1, 2, 3, 4]});

    response.flags = {response: true, opcode: dns.OPCODE.QUERY, replyCode: dns.RCODE.NOERROR, authoritativeAnswer: true};

    console.log(response);
    server.send(response);
});

server.bind('udp6', port=53, block=true);


