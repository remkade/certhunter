certhunter
==========

A golang tool for querying a server and getting information on the SSL certs. This is particularly useful for servers that redirect on the first SSL query.

Building
--------
- Clone the repo
- Run `go build`
- Celebrate!

Usage
=====
The majority of your use cases will be like so:
`./certhunter --host=www.example.com --verbose`

If you are running a cluster of servers and need to figure out which one has an invalid cert you can do something more like this for each server:
`./certhunter --host=web1.example.com --verbose --skip-host-verify`

The skip-host-verify option is necessary since in this example the server would return a www.example.com cert, but the hostname you connect to is the internal server hostname of web1.example.com.

For more info you can always run `./certhunter --help`
