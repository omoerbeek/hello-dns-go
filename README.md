# hello-dns-go
A port/rewrite of the hello-dns project (https://github.com/ahupowerdns/hello-dns.git) in Go

This is project to write a basic DNS recursor in Go. It is based on the hello-dns project by Bert Hubert.
This is for educational and demonstration purposes only. Also, read the LICENSE file.

Currently, it implements two commands

- tdig, a client to talk to a resolver and print the results
- tres, a resolver that can resolve a single query or act as a server, acccepting requests over the net
  and sending back the result.

The common code can be found in the tdns package.

Compared to the code in hello-dns, hello-dns-go has some differences

- Go has no exceptions, so error handling is different and uses the comon Go idiom.
- All in memory data is kept in host byte order and only converted to wire format when sending and 
  converted from wire format when receiving. hello-dns keeps some of it's data in wire format in memory.
- I'm using a different way to compute the compression of dns names.

## Running the code

- To build: 

  `go build cmd/tdig.go`
  
  `go build cmd/tres.go`
  
  This produces two executables, `tdig` and `tres`

- `./tdig name type resolver:port`

  where type is the DNS record type: (A, AAAA, NS, etc) send a query to the specified reolver. IN this case that server will do the recursive query or retrieve the requested data from it's cache. For example: 
  
  `./tdig example.com A 127.0.0.1:53`
- `./tres name type` to do a single shot recursive resolve. This gives a nice idea on how much work is needed to resolve 
  a name if no cache is being used.
- `./tres ip:port` to run as a resolver listening on the specified IP:port combination.
  For example 
  
  `./tres 127.0.0.1:1053`
  
  This will start the resolver, waiting for qeuries from clients.
  You can use `tdig` or any program to query the resolver:
  
  `./tdig example.com NS 127.0.0.1:1053`
  
  `tres` is a very verbose program. This is because it is a learning tool, not a resolver intended for any real-world use.
  That said, it seems to work (albeit very slow since it has no cache) when I configure my laptop to use it as it's main 
  resolver.
  
