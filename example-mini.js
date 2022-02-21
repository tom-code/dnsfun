dns = require('dnsfun')

var server = dns.Create();

server.on_message((request) => {

    console.log(request);

    var response = request.createResponse();

    // respond with not implemented to opcode different than query
    if (request.flagsDecoded.opcode != dns.OPCODE.QUERY) {
        response.flags = {
                           response: true,
                           opcode: request.flagsDecoded.opcode,
                           replyCode: dns.RCODE.NOTIMPL
                         };
        server.send(resp);
        return;
    }

    // respond with loopback to all A and AAAA queries
    for (const query of request.queries) {
        if ((query.type == dns.TYPE.A) && (query.class == dns.CLASS.IN)) {
            response.answers.push({
                                    name: query.name,
                                    type: dns.TYPE.A,
                                    class: dns.CLASS.IN,
                                    ttl: 3600,
                                    data: [127, 0, 0, 1]
                                  });
        }

        if ((query.type == dns.TYPE.AAAA) && (query.class == dns.CLASS.IN)) {
            response.answers.push({
                                    name: query.name,
                                    type: dns.TYPE.AAAA,
                                    class: dns.CLASS.IN,
                                    ttl: 3600,
                                    data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                                  });
        }
    }

    if (response.answers.length > 0) {
        response.flags.replyCode = dns.RCODE.NOERROR;
        authoritativeAnswer = true;
    } else {
        response.flags.replyCode = dns.RCODE.NAMEERROR;
    }

    console.log(response);
    server.send(response);
});

server.bind('udp6', port=53, block=true);


