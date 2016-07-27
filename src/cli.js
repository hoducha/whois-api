#!/usr/bin/env node
import program from 'commander';
import whois from './index';

program
  .version('1.0.2')
  .arguments('<address> [addresses]')
  .option('-r, --raw', 'Display the raw whois response')
  .parse(process.argv);

if (!program.args.length) {
  program.help();
}

if (program.args.length === 1) {
  const lookup = program.raw ? whois.rawLookup : whois.lookup;

  lookup(program.args[0], (error, result) => {
    if (error) {
      console.log(error);
    } else {
      console.log(result);
    }
  });
} else {
  if (program.raw) {
    console.error('--raw option only supports for lookup a single domain');
    process.exit(1);
  }

  whois.multiLookup(program.args, (error, result) => {
    if (error) {
      console.log(error);
    } else {
      console.log(result);
    }
  });
}
