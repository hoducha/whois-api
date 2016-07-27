import async from 'async';
import client from './client';
import parser from './parser';

const rawLookup = client.lookup;

const lookup = (domain, callback) => {
  client.lookup(domain, function(err, data) {
    return callback(err, parser.parse(data));
  });
}

const multiLookup = (domains, callback) => {
  async.mapLimit(domains, 100, lookup, function(err, data) {
    if (data) {
      const result = {};
      for (let i = 0; i < domains.length; i++) {
        result[domains[i]] = data[i];
      }
      return callback(err, result);
    } else {
      return callback(err);
    }
  });
}

module.exports = {
  rawLookup,
  lookup,
  multiLookup
}
