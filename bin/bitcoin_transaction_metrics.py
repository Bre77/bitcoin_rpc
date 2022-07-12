import os
import sys
import json
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import *

def add(obj,key,value):
    if key in obj:
        obj[key] += value
    else:
        obj[key] = value

class Input(Script):
    MASK = "<encrypted>"
    APP = __file__.split(os.sep)[-3]

    def get_scheme(self):

        scheme = Scheme("Bitcoin Transaction Metrics")
        scheme.description = ("Create metrics for all BTC movements")
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(Argument(
            name="username",
            title="RPC Username",
            data_type=Argument.data_type_string,
            required_on_create = True,
            required_on_edit = False
        ))
        scheme.add_argument(Argument(
            name="password",
            title="RPC Password",
            data_type=Argument.data_type_string,
            required_on_create = True,
            required_on_edit = False
        ))
        scheme.add_argument(Argument(
            name="url",
            title="RPC URL",
            data_type=Argument.data_type_string,
            required_on_create = True,
            required_on_edit = False
        ))
        scheme.add_argument(Argument(
            name="startblock",
            title="Starting Block Hash",
            data_type=Argument.data_type_string,
            required_on_create = False,
            required_on_edit = False
        ))
        return scheme

    def stream_events(self, inputs, ew):
        self.service.namespace['app'] = self.APP
        # Get Variables
        input_name, input_items = inputs.inputs.popitem()
        kind, name = input_name.split("://")
        checkpointfile = os.path.join(self._input_definition.metadata["checkpoint_dir"], name)

        # Password Encryption / Decryption
        updates = {}
        for item in ["password"]:
            stored_password = [x for x in self.service.storage_passwords if x.username == item and x.realm == name]
            if input_items[item] == self.MASK:
                if len(stored_password) != 1:
                    ew.log(EventWriter.ERROR,f"Encrypted {item} was not found for {input_name}, reconfigure its value.")
                    return
                input_items[item] = stored_password[0].content.clear_password
            else:
                if(stored_password):
                    ew.log(EventWriter.DEBUG,"Removing Current password")
                    self.service.storage_passwords.delete(username=item,realm=name)
                ew.log(EventWriter.DEBUG,"Storing password and updating Input")
                self.service.storage_passwords.create(input_items[item],item,name)
                updates[item] = self.MASK
        if(updates):
            self.service.inputs.__getitem__((name,kind)).update(**updates)
        
        # Checkpoint
        try:
            height = int(open(checkpointfile, "r").read())
        except:
            height = int(input_items['startblock'])

        TXCACHE = {}

        with requests.Session() as session:
            session.auth = (input_items['username'], input_items['password'])

            getblockhash = session.post(
                input_items['url'],
                json={"jsonrpc":"1.0","id":"splunk","method":"getblockhash","params":[height]}
            )
            nextblock = getblockhash.json()["result"]

            if not nextblock:
                ew.log(EventWriter.INFO,f"No block yet at height: {height}")
                exit()

            ew.log(EventWriter.INFO,f"Starting at block height: {height} hash: {nextblock}")

            while True:
                ew.log(EventWriter.DEBUG,f"Getting Block {nextblock}")
                getblock = session.post(
                    input_items['url'],
                    json={"jsonrpc":"1.0","id":"splunk","method":"getblock","params":[nextblock,2]}
                )

                if not getblock.ok:
                    ew.log(EventWriter.WARN,f"getblock Request failed with status {getblock.status_code}")
                    break

                block = getblock.json()
                if block["error"]:
                    ew.log(EventWriter.WARN,f"getblock Request had error {block['error']}")
                    break

                if not block["result"]['nextblockhash']:
                    break

                for tx in block["result"]["tx"]:
                    addresses = {}
                    for vin in tx["vin"]:
                        if "coinbase" in vin: # mined
                            add(addresses,'COINBASE',-sum(x['value'] for x in tx['vout']))
                        elif "txid" in vin: # use / spend
                            key = f"{vin['txid']} {vin['vout']}"
                            if key in TXCACHE: # check cache
                                add(addresses,TXCACHE[key][0],-TXCACHE[key][1])
                                del TXCACHE[key]
                            else: # get from bitcoind
                                ew.log(EventWriter.DEBUG,f"Getting Transaction {vin['txid']} {vin['vout']}")
                                getvintx = session.post(
                                    input_items['url'],
                                    json={"jsonrpc":"1.0","id":"splunk","method":"getrawtransaction","params":[vin["txid"],True]}
                                )
                                if getvintx.ok:
                                    vintx = getvintx.json()
                                    if vintx["error"]:
                                        ew.log(EventWriter.WARN,f"getrawtransaction Request had error {vintx['error']}")
                                        continue
                                    if vintx['result']:
                                        if "address" in vintx['result']['vout'][vin['vout']]["scriptPubKey"]:
                                            add(addresses,vintx['result']['vout'][vin['vout']]["scriptPubKey"]["address"],-vintx['result']['vout'][vin['vout']]["value"])
                                        else:
                                            ew.log(EventWriter.DEBUG,f"No VIN Address {vin['txid']} {vin['vout']}")
                                    else:
                                        ew.log(EventWriter.ERROR,f"TX {vin['txid']} {vin['vout']} not found: {json.dumps(txout)}")
                                else:
                                    ew.log(EventWriter.WARN,f"getrawtransaction Request failed with status {getvintx.status_code} {getvintx.text}")
                    
                    for vout in tx['vout']: # sent / unspent
                        if("address" in vout["scriptPubKey"]):
                            TXCACHE[f"{tx['txid']} {vout['n']}"] = (vout["scriptPubKey"]["address"],vout["value"]) # add to cache
                            add(addresses,vout["scriptPubKey"]["address"],vout["value"])
                        else:
                            ew.log(EventWriter.DEBUG,f"No VOUT Address {tx['txid']} {vout['n']}")

                    for addr,value in addresses.items():
                        ew.write_event(Event(
                            time=block["result"]['time'],
                            source=input_items['url'],
                            data=json.dumps({
                                "metric_name:btc": round(value,8),
                                "address": addr,
                                "transaction": tx["txid"],
                                "block": block["result"]['hash']
                            }, separators=(',', ':'))
                        ))

                nextblock = block['result']['nextblockhash']
                open(checkpointfile, "w").write(str(block["result"]['height']+1))
        
        ew.close()
        
if __name__ == '__main__':
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)