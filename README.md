try-cb-golang
===============

This is a sample application for getting started with Couchbase Server 6.5 or later. The application runs a single page UI
and demonstrates SQL for Documents (N1QL) and Full Text Search (FTS) querying capabilities. It uses Couchbase Server 6.5+
together with Vue and Bootstrap.

The application is a flight planner that allows the user to search for and select a flight route (including the
return flight) based on airports and dates. Airport selection is done dynamically using an autocomplete box
bound to N1QL queries on the server side. After selecting a date, it then searches for applicable air flight routes from
a previously populated database. An additional page allows users to search for Hotels using less structured keywords.

## Installation and Configuration
The steps below assume you are running a standalone couchbase instance running kv, indexing, fts (in Couchbase 4.5 or
later) and query services on the same server where the node application will also be running.

 1. Install a Couchbase Server, start it, and load the `travel-sample` bucket.
    * If you want to use Full-Text Search, set up an FTS index called `hotels` for all documents of type `hotel`.  More information on how to set up an FTS index can be found [here](https://docs.couchbase.com/server/current/fts/fts-creating-indexes.html).

 2. Run the included `create-collections.sh` script to set up the correct collections
 ```bash
 ./create-collections.sh Adminstrator password localhost
 ```
 3. Install Go 1.13+

 4. Ensure `GO111MODULE=on` is set in your environment variables.

 5. Run `go get` from the terminal to fetch this repo and it will be downloaded in your $GOPATH: 
      * If you don't know where your $GOPATH directory is located, you can run `go env` to find out.

 ```bash
 go get -u "github.com/couchbaselabs/try-cb-golang"
 ```

 6. Start the application by running the binary from your $GOPATH/bin directory. From a terminal:

 ```bash
 cd $GOPATH/bin
 ./try-cb-golang
 ```

 7. Open a browser and load the url http://localhost:8080

## REST API DOCUMENTATION
The REST API for this example application can be found at:
[https://github.com/couchbaselabs/try-cb-frontend/blob/master/documentation/try-cb-api-spec-v2.adoc](https://github.com/couchbaselabs/try-cb-frontend/blob/master/documentation/try-cb-api-spec-v2.adoc)
