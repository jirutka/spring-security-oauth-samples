These are the Spring Security OAuth sample apps and integration tests.
There are two web apps, one (`sparklr`) is a resource & authorization
server, and the other (`tonr`) is a client (consumer of the
services).  The `tonr` app is also able to consume external resources
(e.g. Facebook), and the precise external resource it consumes has
been chosen to show the use of the relevant protocol.

The `sparklr` app is a photo storage and browsing service, but it
doesn't know how to print your photos.  Thats where `tonr` comes in.
You go to `tonr` to browse the photos that are stored in `sparklr` and
"print" them (this feature is not actually implemented).  The `tonr`
app has to get your permission to access the photos, but only for read
access - this is the key separation of concerns that is offered by
OAuth protocols: `sparklr` is able to ask the user to authorize `tonr`
to read his photos for the purpose of printing them.

To run the apps the easiest thing is to first install all the
artifacts using `mvn install` and then go to the `tonr` directory
and run `mvn tomcat:run`.  You can also use the command line to build 
war files with `mvn package` and drop them in your favourite server, 
or you can run them directly from an IDE.

Visit `http://localhost:8080/tonr2` in a browser and go to the
`sparklr` tab.  The result should be:

* You are prompted to authenticate with `tonr` (the login screen tells
  you the users available and their passwords)
  
* The correct authorization is not yet in place for `tonr` to access
  your photos on `sparklr` on your behalf, so `tonr` redirects your
  browser to the `sparklr` UI to get the authorization.

* You are prompted to authenticate with `sparklr`.

* Then `sparklr` will ask you if you authorize `tonr` to access your
  photos.
  
* If you say "yes" then your browser will be redirected back to `tonr`
  and this time the correct authorization is present, so you will be
  able to see your photos.

## How to build the WAR files

Use Maven (2.2.1 works) and, from this directory do 

    $ mvn package

and then look in `{sparklr,tonr}/target` for the war files.  Deploy
them with context roots `{/sparklr2,/tonr2}` in your favourite web
container, and fire up the `tonr` app to see the two working together.
