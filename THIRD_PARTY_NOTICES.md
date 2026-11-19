# Third-party notices

ua-rust is licensed under Apache-2.0. It vendors the files below, which keep
their own licenses. Rust crate dependencies are listed in `Cargo.lock`; their
licenses travel with their sources on crates.io.

## htmx 2.0.11

- File: `crates/ua-server/static/htmx-2.0.11.min.js` (unmodified
  `dist/htmx.min.js` from the `htmx.org` npm package, version 2.0.11)
- Upstream: https://github.com/bigskysoftware/htmx
- License: 0BSD

```
Zero-Clause BSD
=============

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

## htmx SSE extension 2.2.4

- File: `crates/ua-server/static/htmx-ext-sse-2.2.4.js` (unmodified
  `dist/sse.js` from the `htmx-ext-sse` npm package, version 2.2.4)
- Upstream: https://github.com/bigskysoftware/htmx-extensions
- License: 0BSD

```
BSD Zero Clause License

Copyright (c) 2023, Alexander Petros

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

To upgrade either file, replace it with the new release's unmodified
distribution file, rename it with the new version, update the `<script>` tags
in `crates/ua-server/templates/ui/base.html`, and update this page.
