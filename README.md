# Whois API

A lightweight Whois Client and Parser written in Javascript.

## Installation

### Global
```bash
  $ npm install -g whois-api
```

#### CLI usage
```bash
  Usage: whois-api [options] <address> [addresses]

  Options:

    -h, --help     output usage information
    -V, --version  output the version number
    -r, --raw      Display the raw whois response
```

### Local
```bash
    $ npm install whois-api
```

#### Basic usage

```js
import whois from 'whois-api';

whois.lookup('trello.com', (error, result) => {
  console.log(result);
});
```

#### Lookup for multiple domains
```js
whois.multiLookup(['trello.com', 'example.com'], (error, result) => {
  console.log(result);
});
```

#### Raw lookup
```js
whois.rawLookup('trello.com', (error, result) => {
  console.log(result);
});
```

## Contributing

Contributions are welcome.

## License

Whois API is available under the [BSD (2-Clause) License](http://opensource.org/licenses/BSD-2-Clause).
