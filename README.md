# Whois API

An independent Whois Client and Parser written in Javascript.

## Installation

### Global

  $ npm install -g whois

#### CLI usage

  Usage: whois-api [options] <address> [addresses]

  Options:

    -h, --help     output usage information
    -V, --version  output the version number
    -r, --raw      Display the raw whois response

### Local

    $ npm install whois-api

#### Usage

```js
import whois from 'whois-api';

whois.lookup('trello.com', (error, result) => {
  console.log(result);
});
```

Lookup for multiple domains
```js
whois.multiLookup(['trello.com', 'example.com'], (error, result) => {
  console.log(result);
});
```

Raw lookup
```js
whois.rawLookup('trello.com', (error, result) => {
  console.log(result);
});
```

## Contributing

Contributions are welcome.

## License

Node WHOIS is available under the [BSD (2-Clause) License](http://opensource.org/licenses/BSD-2-Clause).
