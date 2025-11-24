# sha1sum

> Just your average, everyday SHA-1 implementation.

1. Build with `cargo build` or `cargo build --release` and then `cd target/debug` or `cd target/release`.

2. Pipe some data in like you would with any other CLI application:

`echo -n "hello" | sha1sum`

or

3. Give it a file path containing your favorite data:

`sha1sum /path/to/file`

4. Enjoy the fruits of your labor
