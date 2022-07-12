Modular Input for the Bitcoind JSON-RPC API

Required bitcoind to be running with the following:
```
server=1
txindex=1                                                                                                                                                             
rpcuser=<username>                                                                                                                                                             
rpcpassword=<password>
```

By default, Splunk indexes only keeps data 6 years old, and this input is designed to ingest data from January 3 2009, so you will need to increase the frozenTimePeriodInSecs significantly.

splunkbase@ba.id.au