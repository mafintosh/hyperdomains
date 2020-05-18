# hyperdomains

Experimental none enumerable trie for stuff like domains

```
npm install hyperdomains
```

## Usage

``` js
const HyperDomains = require('hyperdomains')
const domains = new HyperDomains(storage, key)

domains.register('foo', hypercoreKey, cb)
domains.lookup('foo', cb)
```

## License

MIT
