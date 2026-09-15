<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# JavaScript drop-in

`zbc.js` is the TypeScript package (`../ts`) bundled into one file with no dependencies: keys,
addresses, `ZBC-MSG-v1` message signing, the transaction envelope and chain-bound digest, every
transaction body of `../spec/transactions`, and the node client on the browser's `fetch`. It is
committed so nobody needs npm; `../ts/scripts/bundle.mjs` rebuilds it and CI checks it is current.

```html
<script src="zbc.js"></script>
<script>
  const kp = ZBC.keyPairFromSeed("<64 hex seed>");
  console.log(kp.address);                                              // ZBC_...
  const s = ZBC.signMessage(kp.seed, ZBC.utf8("hello"));                // { address, digest, signature, ... }
  console.log(ZBC.verifyMessage(kp.address, ZBC.utf8("hello"), s.signature));   // true

  const client = new ZBC.Client({ api: "https://<gateway>" });
  client.signingRule().then((ctx) => {
    const tx = ZBC.signTransaction({
      type: 1, timestamp: Math.floor(Date.now() / 1000), sender: kp.accountBytes,
      recipient: ZBC.parseAddress("ZBC_...").bytes, fee: 5000000n, body: ZBC.sendZbcBody(100000000n),
    }, kp, ctx);
    return client.submitOrThrow(tx.payload);
  });
</script>
```

Offline: `ZBC.signingContext("<genesis hex>")` in place of `client.signingRule()`. Everything the
TypeScript README documents is on the `ZBC` global; in Node the same file loads with
`require("./zbc.js")`. It needs a browser or runtime with `BigInt`, `TextEncoder`, `fetch` and
`crypto.getRandomValues` (every current browser, Node 20 or newer).
