# json2dir-mojo

[json2dir](https://github.com/kitsunoff/awesome-json2dir) in Mojo: one file, Mojo standard library only (hand-written JSON parser, libc via `external_call`).

    mojo build json2dir.mojo -o json2dir && ./json2dir < document.json
