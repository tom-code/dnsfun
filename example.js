const { response } = require('express');





dns = require('./dns.js')

var server = dns.Create();
server.on_message((request) => {
    console.log(request);
    var resp = request.createResponse();
    if (request.flagsDecoded.opcode != dns.OPCODE.QUERY) {
        resp.flags = {response: true, opcode: request.flagsDecoded.opcode, replyCode: dns.RCODE.NOTIMPL};
        server.send(resp);
        return;
    }

    resp.answers = [];
    // respond with 127.0.0.1 to all A queries
    for (const query of request.queries) {
        if ((query.type == dns.TYPE.A) && (query.class == dns.CLASS.IN)) {
            resp.answers.push({name: query.name, type: dns.TYPE.A, class: dns.CLASS.IN, ttl: 3600, data: [127, 0, 0, 1]});
            resp.answerRRs += 1;
        }
    }

    // add funny aaaa record
    resp.answers.push({name: "v6.fun", type: dns.TYPE.AAAA, class: dns.CLASS.IN, ttl: 3600, data: [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]});
    resp.answerRRs += 1;

    // add also srv record for fun
    var srv = {priority: 1, weight: 3, port: 1212, target: "x.y.z"}
    resp.answers.push({name: "_svc._proto.name", type: dns.TYPE.SRV, class: dns.CLASS.IN, ttl: 3600, data: srv});
    resp.answerRRs += 1;

    resp.flags = {response: true, opcode: dns.OPCODE.QUERY, replyCode: dns.RCODE.NOERROR};
    console.log(resp);
    server.send(resp);
});

server.bind('udp6', port=53, block=true);


