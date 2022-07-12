import os
import sys
import json
import requests
import binascii
import hashlib


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import *
import base58

def P2PKHToAddress(pkscript):
    pub = pkscript[6:-4] # get pkhash, inbetween first 3 bytes and last 2 bytes
    p = '00' + pub # prefix with 00 if it's mainnet
    h1 = hashlib.sha256(binascii.unhexlify(p))
    h2 = hashlib.new('sha256', h1.digest())
    h3 = h2.hexdigest()
    a = h3[0:8] # first 4 bytes
    c = p + a # add first 4 bytes to beginning of pkhash
    d = int(c, 16) # string to decimal
    b = d.to_bytes((d.bit_length() + 7) // 8, 'big') # decimal to bytes
    address = '1' + base58.b58encode(b) # bytes to base58
    return address


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
                exit()

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
                #ew.log(EventWriter.INFO,json.dumps(block))
                print(block)
                if block["error"]:
                    ew.log(EventWriter.WARN,f"getblock Request had error {block['error']}")
                    break

                if not block["result"]['nextblockhash']:
                    break

                for tx in block["result"]["tx"]:
                    for vin in tx["vin"]:
                        if "coinbase" in vin: # mined
                            ew.write_event(Event(
                                time=block["result"]['time'],
                                source=input_items['url'],
                                data=json.dumps({
                                    "metric_name:btc": -sum(x['value'] for x in tx['vout']),
                                    "address": "COINBASE",
                                    "transaction": tx["txid"],
                                    "block": block["result"]['hash']
                                }, separators=(',', ':'))
                            ))
                        elif("txid" in vin): # unspent
                            key = f"{vin['txid']} {vin['vout']}"
                            if key in TXCACHE: # check memory
                                ew.log(EventWriter.INFO,f"Got {key} from cache!")
                                ew.write_event(Event(
                                    time=block["result"]['time'],
                                    source=input_items['url'],
                                    data=json.dumps({
                                        "metric_name:btc": TXCACHE[key][0],
                                        "address": TXCACHE[key][1],
                                        "transaction": tx["txid"],
                                        "block": block["result"]['hash']
                                    }, separators=(',', ':'))
                                ))
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
                                    if vintx['result']['vout'][vin['vout']]:
                                        if "address" in vintx['result']['vout'][vin['vout']]["scriptPubKey"]:
                                            addr = vintx['result']['vout'][vin['vout']]["scriptPubKey"]['address']
                                        else:
                                            addr = P2PKHToAddress(vintx['result']['vout'][vin['vout']]["scriptPubKey"]['hex'])
                                        ew.write_event(Event(
                                            time=block["result"]['time'],
                                            source=input_items['url'],
                                            data=json.dumps({
                                                "metric_name:btc": -vintx['result']['vout'][vin['vout']]["value"],
                                                "address": addr,
                                                "transaction": tx["txid"],
                                                "block": block["result"]['hash']
                                            }, separators=(',', ':'))
                                        ))
                                        #else:
                                        #    ew.log(EventWriter.WARN,f"No VIN Address {vin['txid']} {vin['vout']}")
                                    else:
                                        ew.log(EventWriter.ERROR,f"TX {vin['txid']} {vin['vout']} not found: {json.dumps(txout)}")
                                else:
                                    ew.log(EventWriter.WARN,f"getrawtransaction Request failed with status {getvintx.status_code} {getvintx.text}")
                    
                    for vout in tx['vout']: # spend
                        if("address" in vout["scriptPubKey"]):
                            addr = vout["scriptPubKey"]['address']
                        else:
                            addr = P2PKHToAddress(vout["scriptPubKey"]['hex'])
                        TXCACHE[f"{tx['txid']} {tx['n']}"] = (addr,vout["value"])
                        ew.write_event(Event(
                            time=block["result"]['time'],
                            source=block["result"]['hash'],
                            data=json.dumps({
                                "metric_name:btc": vout["value"],
                                "address": addr,
                                "transaction":tx['txid'],
                                "block": block["result"]['hash']
                            }, separators=(',', ':'))
                        ))
                        #else:
                        #    ew.log(EventWriter.WARN,f"No VOUT Address {tx['txid']} {vout['n']}")


                nextblock = block['result']['nextblockhash']
                open(checkpointfile, "w").write(str(block["result"]['height']+1))
        
        ew.close()
        
if __name__ == '__main__':
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)