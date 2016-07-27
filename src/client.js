import net from 'net';
import _ from 'lodash';
import punycode from 'punycode';
import SERVERS from './servers.json';

const validateAddress = (address) => {
  switch (true) {
    case !address:
      return new Error('Address is empty');
    case address.indexOf(':') > -1:
      return new Error('IPv6 not supported');
    case address.indexOf('@') > -1:
      return new Error('Email not supported');
    default:
      return null;
  }
}

const isIPv4 = (address) => {
  return (address.match(/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/)) != null;
}

const getServer = (address, aSpecificServer) => {
  let server;
  if (aSpecificServer) {
    server = aSpecificServer;
  } else {
    if (isIPv4(address)) {
      server = SERVERS['_']['ipv4'];
    } else {
      let tld = punycode.toASCII(address);
      while (true) {
        server = SERVERS[tld];
        if (!tld || server) {
          break;
        }
        tld = tld.replace(/^.+?(\.|$)/, '');
      }
    }
  }

  if (server) {
    if (typeof server === 'string') {
      const parts = server.split(':');
      server = {
        host: parts[0],
        port: parts[1]
      };
    }
    _.defaults(server, {
      port: 43,
      query: "$addr\r\n"
    });
  }

  return server;
}

const lookup = (address, options, callback) => {
  if (typeof done === 'undefined' && typeof options === 'function') {
    callback = options;
    options = {};
  }

  _.defaults(options, {
    follow: 2
  });

  callback = _.once(callback);

  let validationError = validateAddress(address);
  if (validationError) {
    return callback(validationError);
  }

  const server = getServer(address, options.server);
  if (!server) {
    return callback(new Error('No WHOIS server found for the address'));;
  }

  const socket = net.connect(server.port, server.host, function() {
    let idn = punycode.toASCII(address);
    return socket.write(server.query.replace('$addr', idn));
  });
  socket.setEncoding('utf-8');

  let data = '';
  socket.on('data', function(chunk) {
    return data += chunk;
  });
  socket.on('timeout', function() {
    return callback(new Error('Connection timeout'));
  });
  socket.on('error', function(err) {
   return callback(err);
  });

  return socket.on('close', function(err) {
    if (options.follow > 0) {
      const match = data.match(/(ReferralServer|Registrar Whois|Whois Server):\s*(r?whois:\/\/)?(.+)/);
      if (match != null) {
        options = _.extend({}, options, {
          follow: options.follow - 1,
          server: match[3]
        });
        lookup(address, options, function(err, parts) {
          if (err != null) {
            return callback(err);
          }
          if (options.verbose) {
            return callback(null, [{
              server: server,
              data: data
            }].concat(parts));
          } else {
            return callback(null, parts);
          }
        });
        return;
      }
    }

    if (options.verbose) {
      return callback(null, [{
          server: server,
          data: data
        }]);
    } else {
      return callback(null, data);
    }
  });
}

module.exports = {
  lookup
}
